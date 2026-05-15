package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// wsInternalHost is the hostname the proxy uses in the relay URL to signal a
// WebSocket session operation. The VPS relay intercepts requests to this host
// before making any outbound HTTP request, so GAS passes them through as-is.
const wsInternalHost = "ws.zyrln.internal"

// wsDialCtx is the dial function used by WebSocket session connects.
// Set once in main() to match the transport's dialer (plain TCP or SOCKS5).
var wsDialCtx func(ctx context.Context, network, addr string) (net.Conn, error)

// ── WebSocket opcodes ─────────────────────────────────────────────────────────

const (
	vpsWsOpContinuation byte = 0x0
	vpsWsOpText         byte = 0x1
	vpsWsOpBinary       byte = 0x2
	vpsWsOpClose        byte = 0x8
	vpsWsOpPing         byte = 0x9
	vpsWsOpPong         byte = 0xA
)

// ── WebSocket frame codec (VPS acts as client: sends masked, reads unmasked) ──

func vpsReadWSFrame(r io.Reader) (op byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	op = hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	payLen := int(hdr[1] & 0x7F)

	switch payLen {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return
		}
		payLen = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint64(ext[:])
		const maxPay = 16 << 20
		if n > maxPay {
			err = fmt.Errorf("ws frame too large: %d", n)
			return
		}
		payLen = int(n)
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(r, maskKey[:]); err != nil {
			return
		}
	}

	payload = make([]byte, payLen)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return
}

func vpsWriteWSFrame(conn net.Conn, op byte, payload []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

	b0 := byte(0x80) | op // FIN set, opcode
	payLen := len(payload)

	var hdr []byte
	hdr = append(hdr, b0)
	// Client MUST mask frames (RFC 6455 §5.3)
	const maskBit = byte(0x80)
	switch {
	case payLen < 126:
		hdr = append(hdr, maskBit|byte(payLen))
	case payLen < 65536:
		hdr = append(hdr, maskBit|126, byte(payLen>>8), byte(payLen))
	default:
		hdr = append(hdr, maskBit|127, 0, 0, 0, 0,
			byte(payLen>>24), byte(payLen>>16), byte(payLen>>8), byte(payLen))
	}

	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("ws mask key: %w", err)
	}
	hdr = append(hdr, key[:]...)

	masked := make([]byte, payLen)
	for i, b := range payload {
		masked[i] = b ^ key[i%4]
	}

	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(masked)
	return err
}

// ── Session store ─────────────────────────────────────────────────────────────

// wsRelayFrame is the JSON wire format for a single WebSocket frame.
type wsRelayFrame struct {
	Opcode  byte   `json:"opcode"`
	Payload string `json:"payload"` // base64-encoded
}

// wsSession holds an active WebSocket connection to an upstream server.
type wsSession struct {
	mu        sync.Mutex
	conn      net.Conn
	reader    *bufio.Reader
	recvBuf   []wsRelayFrame
	notify    chan struct{} // closed & replaced when new frames arrive or session closes
	closed    bool
	closeOnce sync.Once
	lastPoll  time.Time
}

// addFrame appends a frame to the receive buffer and signals any waiting recv.
func (s *wsSession) addFrame(f wsRelayFrame) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.recvBuf = append(s.recvBuf, f)
	old := s.notify
	s.notify = make(chan struct{})
	s.mu.Unlock()
	close(old)
}

// closeSession marks the session as closed, closes the upstream connection,
// and unblocks any goroutine waiting in recv.
func (s *wsSession) closeSession() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		old := s.notify
		s.notify = make(chan struct{}) // never closed again
		s.mu.Unlock()
		close(old)
		_ = s.conn.Close()
	})
}

// isClosed reports whether the session has been closed.
func (s *wsSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// readLoop is the background goroutine that reads frames from the upstream
// WebSocket server and buffers them for ws-recv polls.
func (s *wsSession) readLoop() {
	defer s.closeSession()
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		op, payload, err := vpsReadWSFrame(s.reader)
		if err != nil {
			return
		}
		switch op {
		case vpsWsOpClose:
			return
		case vpsWsOpPing:
			// Respond with Pong; hold the write lock to prevent concurrent writes
			s.mu.Lock()
			_ = vpsWriteWSFrame(s.conn, vpsWsOpPong, payload)
			s.mu.Unlock()
		default:
			s.addFrame(wsRelayFrame{
				Opcode:  op,
				Payload: base64.StdEncoding.EncodeToString(payload),
			})
		}
	}
}

// Global session store.
var sessStore sync.Map // string → *wsSession

func init() { go sessionCleanupLoop() }

// sessionCleanupLoop removes idle sessions every two minutes.
func sessionCleanupLoop() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		sessStore.Range(func(k, v any) bool {
			sess := v.(*wsSession)
			sess.mu.Lock()
			idle := now.Sub(sess.lastPoll)
			sess.mu.Unlock()
			if idle > 5*time.Minute {
				v.(*wsSession).closeSession()
				sessStore.Delete(k)
				log.Printf("ws session %s evicted (idle)", k)
			}
			return true
		})
	}
}

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ── Operation router ──────────────────────────────────────────────────────────

// handleWSOperation routes ws.zyrln.internal requests to the appropriate
// session operation handler.
func handleWSOperation(w http.ResponseWriter, req *relayRequest, timeout time.Duration) {
	u, err := url.Parse(req.URL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, relayResponse{Error: "bad url"})
		return
	}

	var body []byte
	if req.Body != "" {
		body, err = base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, relayResponse{Error: "bad base64 body"})
			return
		}
	}

	switch u.Path {
	case "/connect":
		handleWSConnect(w, body, timeout)
	case "/recv":
		handleWSRecv(w, body, timeout)
	case "/send":
		handleWSSend(w, body)
	case "/close":
		handleWSClose(w, body)
	default:
		writeJSON(w, http.StatusNotFound, relayResponse{Error: "unknown ws op: " + u.Path})
	}
}

// ── ws-connect ────────────────────────────────────────────────────────────────

type wsConnectBody struct {
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
}

func handleWSConnect(w http.ResponseWriter, body []byte, timeout time.Duration) {
	var req wsConnectBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, relayResponse{Error: "bad connect body: " + err.Error()})
		return
	}

	target, err := url.Parse(req.Target)
	if err != nil || (target.Scheme != "wss" && target.Scheme != "ws") {
		writeJSON(w, http.StatusBadRequest, relayResponse{Error: "invalid target url"})
		return
	}

	host := target.Hostname()
	port := target.Port()
	if port == "" {
		if target.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialFn := wsDialCtx
	if dialFn == nil {
		dialFn = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}

	rawConn, err := dialFn(ctx, "tcp", addr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, relayResponse{Error: "dial: " + err.Error()})
		return
	}

	var conn net.Conn = rawConn
	if target.Scheme == "wss" {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"}, // no h2: we need HTTP/1.1 for Upgrade
		})
		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			writeJSON(w, http.StatusBadGateway, relayResponse{Error: "tls: " + err.Error()})
			return
		}
		conn = tlsConn
	}

	// Generate a random Sec-WebSocket-Key (the proxy handles the browser's key)
	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	wsKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	// Build the HTTP/1.1 upgrade request
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", target.Host)
	fmt.Fprintf(&reqBuf, "Connection: Upgrade\r\n")
	fmt.Fprintf(&reqBuf, "Upgrade: websocket\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Key: %s\r\n", wsKey)
	for k, v := range req.Headers {
		if !skipWSHeader(k) {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	fmt.Fprintf(&reqBuf, "\r\n")

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprint(conn, reqBuf.String()); err != nil {
		_ = conn.Close()
		writeJSON(w, http.StatusBadGateway, relayResponse{Error: "write upgrade: " + err.Error()})
		return
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = conn.Close()
		writeJSON(w, http.StatusBadGateway, relayResponse{Error: "read upgrade response: " + err.Error()})
		return
	}
	_ = resp.Body.Close()
	_ = conn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		writeJSON(w, http.StatusBadGateway, relayResponse{
			Error: fmt.Sprintf("ws upgrade got %d", resp.StatusCode),
		})
		return
	}

	sessID, err := newSessionID()
	if err != nil {
		_ = conn.Close()
		writeJSON(w, http.StatusInternalServerError, relayResponse{Error: "session id: " + err.Error()})
		return
	}
	sess := &wsSession{
		conn:     conn,
		reader:   reader,
		notify:   make(chan struct{}),
		lastPoll: time.Now(),
	}
	sessStore.Store(sessID, sess)
	go sess.readLoop()

	type connectResp struct {
		Session string `json:"session"`
		Status  int    `json:"status"`
	}
	result, _ := json.Marshal(connectResp{Session: sessID, Status: http.StatusSwitchingProtocols})
	log.Printf("ws-connect %s → session %.8s…", addr, sessID)
	writeRelayBody(w, result)
}

func skipWSHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "upgrade", "sec-websocket-key",
		"sec-websocket-version", "host",
		"content-length", "transfer-encoding":
		return true
	}
	return false
}

// ── ws-recv ───────────────────────────────────────────────────────────────────

func handleWSRecv(w http.ResponseWriter, body []byte, _ time.Duration) {
	type recvBody struct {
		Session   string `json:"session"`
		TimeoutMs int    `json:"timeout_ms"`
	}
	type recvResp struct {
		Frames []wsRelayFrame `json:"frames"`
		Closed bool           `json:"closed"`
	}

	var req recvBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, relayResponse{Error: "bad recv body"})
		return
	}

	v, ok := sessStore.Load(req.Session)
	if !ok {
		result, _ := json.Marshal(recvResp{Frames: []wsRelayFrame{}, Closed: true})
		writeRelayBody(w, result)
		return
	}
	sess := v.(*wsSession)

	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 || timeoutMs > 25_000 {
		timeoutMs = 25_000
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)

	var frames []wsRelayFrame
	closed := false

	for {
		sess.mu.Lock()
		frames = sess.recvBuf
		sess.recvBuf = nil
		closed = sess.closed
		notify := sess.notify
		sess.lastPoll = time.Now()
		sess.mu.Unlock()

		if len(frames) > 0 || closed {
			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			frames = []wsRelayFrame{}
			break
		}

		timer := time.NewTimer(remaining)
		select {
		case <-notify:
			timer.Stop()
			// frames may have arrived; loop to drain
		case <-timer.C:
			frames = []wsRelayFrame{}
		}
	}

	if frames == nil {
		frames = []wsRelayFrame{}
	}
	result, _ := json.Marshal(recvResp{Frames: frames, Closed: closed})
	writeRelayBody(w, result)
}

// ── ws-send ───────────────────────────────────────────────────────────────────

func handleWSSend(w http.ResponseWriter, body []byte) {
	type sendBody struct {
		Session string         `json:"session"`
		Frames  []wsRelayFrame `json:"frames"`
	}
	type sendResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}

	var req sendBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, relayResponse{Error: "bad send body"})
		return
	}

	v, ok := sessStore.Load(req.Session)
	if !ok {
		result, _ := json.Marshal(sendResp{OK: false, Error: "session not found"})
		writeRelayBody(w, result)
		return
	}
	sess := v.(*wsSession)

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.closed {
		result, _ := json.Marshal(sendResp{OK: false, Error: "session closed"})
		writeRelayBody(w, result)
		return
	}

	for _, f := range req.Frames {
		payload, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			result, _ := json.Marshal(sendResp{OK: false, Error: fmt.Sprintf("frame base64 decode: %v", err)})
			writeRelayBody(w, result)
			return
		}
		if err := vpsWriteWSFrame(sess.conn, f.Opcode, payload); err != nil {
			result, _ := json.Marshal(sendResp{OK: false, Error: "write: " + err.Error()})
			writeRelayBody(w, result)
			return
		}
	}

	result, _ := json.Marshal(sendResp{OK: true})
	writeRelayBody(w, result)
}

// ── ws-close ──────────────────────────────────────────────────────────────────

func handleWSClose(w http.ResponseWriter, body []byte) {
	type closeBody struct {
		Session string `json:"session"`
	}

	var req closeBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, relayResponse{Error: "bad close body"})
		return
	}

	if v, ok := sessStore.LoadAndDelete(req.Session); ok {
		v.(*wsSession).closeSession()
	}

	result, _ := json.Marshal(map[string]bool{"ok": true})
	writeRelayBody(w, result)
}

// ── helper ────────────────────────────────────────────────────────────────────

// writeRelayBody wraps resultJSON in a relayResponse with base64-encoded body,
// matching the format that the relay client expects.
func writeRelayBody(w http.ResponseWriter, resultJSON []byte) {
	writeJSON(w, http.StatusOK, relayResponse{
		Status: http.StatusOK,
		Body:   base64.StdEncoding.EncodeToString(resultJSON),
	})
}
