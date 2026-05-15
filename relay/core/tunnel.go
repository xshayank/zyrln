package core

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// wsInternalBase is the URL prefix used for WebSocket session operations.
// The VPS relay intercepts requests to this host and handles them locally,
// so GAS passes them through unchanged (the URL looks like a normal https://).
const wsInternalBase = "https://ws.zyrln.internal/"

// wsRelayFrame is the wire representation of a single WebSocket frame used in
// the relay protocol between the client proxy and the VPS relay.
type wsRelayFrame struct {
	Opcode  byte   `json:"opcode"`
	Payload string `json:"payload"` // base64-encoded raw payload bytes
}

// wsRelayConnect asks the VPS relay to open a WebSocket connection to
// targetWSURL (a wss:// or ws:// URL) and returns an opaque session ID.
func wsRelayConnect(coal *Coalescer, targetWSURL string, headers map[string]string) (string, error) {
	type connectBody struct {
		Target  string            `json:"target"`
		Headers map[string]string `json:"headers"`
	}
	type connectResp struct {
		Session string `json:"session"`
		Error   string `json:"error,omitempty"`
	}

	body, _ := json.Marshal(connectBody{Target: targetWSURL, Headers: headers})
	resp, err := coal.Submit("POST", wsInternalBase+"connect",
		map[string]string{"Content-Type": "application/json"}, body)
	if err != nil {
		return "", fmt.Errorf("ws-connect relay: %w", err)
	}
	var cr connectResp
	if err := json.Unmarshal(resp.Body, &cr); err != nil {
		return "", fmt.Errorf("ws-connect parse: %w", err)
	}
	if cr.Error != "" {
		return "", fmt.Errorf("ws-connect: %s", cr.Error)
	}
	if cr.Session == "" {
		return "", fmt.Errorf("ws-connect: empty session id")
	}
	return cr.Session, nil
}

// wsRelayRecv polls the VPS relay for incoming WebSocket frames on sessionID.
// It blocks on the VPS for up to timeoutMs milliseconds. Returns the decoded
// frames, a closed flag (true when the upstream session has ended), and any
// transport error.
func wsRelayRecv(coal *Coalescer, sessionID string, timeoutMs int) ([]wsFrame, bool, error) {
	type recvBody struct {
		Session   string `json:"session"`
		TimeoutMs int    `json:"timeout_ms"`
	}
	type recvResp struct {
		Frames []wsRelayFrame `json:"frames"`
		Closed bool           `json:"closed"`
	}

	body, _ := json.Marshal(recvBody{Session: sessionID, TimeoutMs: timeoutMs})
	resp, err := coal.Submit("POST", wsInternalBase+"recv",
		map[string]string{"Content-Type": "application/json"}, body)
	if err != nil {
		return nil, false, fmt.Errorf("ws-recv relay: %w", err)
	}
	var rr recvResp
	if err := json.Unmarshal(resp.Body, &rr); err != nil {
		return nil, false, fmt.Errorf("ws-recv parse: %w", err)
	}

	frames := make([]wsFrame, 0, len(rr.Frames))
	for _, f := range rr.Frames {
		payload, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			continue
		}
		frames = append(frames, wsFrame{Fin: true, Opcode: f.Opcode, Payload: payload})
	}
	return frames, rr.Closed, nil
}

// wsRelaySend sends WebSocket frames to the upstream server via the VPS relay.
func wsRelaySend(coal *Coalescer, sessionID string, frames []wsFrame) error {
	type sendBody struct {
		Session string         `json:"session"`
		Frames  []wsRelayFrame `json:"frames"`
	}
	type sendResp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}

	relayFrames := make([]wsRelayFrame, len(frames))
	for i, f := range frames {
		relayFrames[i] = wsRelayFrame{
			Opcode:  f.Opcode,
			Payload: base64.StdEncoding.EncodeToString(f.Payload),
		}
	}

	body, _ := json.Marshal(sendBody{Session: sessionID, Frames: relayFrames})
	resp, err := coal.Submit("POST", wsInternalBase+"send",
		map[string]string{"Content-Type": "application/json"}, body)
	if err != nil {
		return fmt.Errorf("ws-send relay: %w", err)
	}
	var sr sendResp
	if err := json.Unmarshal(resp.Body, &sr); err != nil {
		return fmt.Errorf("ws-send parse: %w", err)
	}
	if !sr.OK {
		return fmt.Errorf("ws-send: %s", sr.Error)
	}
	return nil
}

// wsRelayClose closes the VPS relay session. Errors are silently ignored
// because the session may have already been cleaned up server-side.
func wsRelayClose(coal *Coalescer, sessionID string) {
	type closeBody struct {
		Session string `json:"session"`
	}
	body, _ := json.Marshal(closeBody{Session: sessionID})
	_, _ = coal.Submit("POST", wsInternalBase+"close",
		map[string]string{"Content-Type": "application/json"}, body)
}

// skipWSProxyHeader reports whether header k is a hop-by-hop or key-specific
// WebSocket header that should not be forwarded from the browser to the relay.
func skipWSProxyHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "upgrade", "sec-websocket-key",
		"proxy-connection", "proxy-authorization",
		"host", "content-length", "transfer-encoding":
		return true
	}
	return false
}

// handleWebSocketViaRelay proxies a WebSocket upgrade intercepted from the
// MITM TLS connection through the GAS → VPS relay chain.
//
// The browser's TLS connection is in clientConn (with clientReader as its
// buffered wrapper). req is the already-parsed WebSocket upgrade request.
// certHost is the bare hostname (for Sec-WebSocket-Accept computation) and
// targetHost is host:port.
func handleWebSocketViaRelay(clientConn net.Conn, clientReader *bufio.Reader,
	req *http.Request, certHost, targetHost string, coal *Coalescer) {

	// Construct the wss:// target URL
	wsTarget := "wss://" + targetHost + req.URL.RequestURI()

	// Collect headers to forward, dropping hop-by-hop / key-specific ones
	hdrs := make(map[string]string)
	for k, vs := range req.Header {
		if len(vs) > 0 && !skipWSProxyHeader(k) {
			hdrs[k] = vs[0]
		}
	}

	// Open a WebSocket session through GAS → VPS
	sessionID, err := wsRelayConnect(coal, wsTarget, hdrs)
	if err != nil {
		logf("error", "ws-connect %s: %v", targetHost, err)
		writeHTTPError(clientConn, http.StatusBadGateway, "WebSocket connect: "+err.Error())
		return
	}

	// Compute the correct Sec-WebSocket-Accept for the browser using its key
	accept := wsComputeAccept(req.Header.Get("Sec-WebSocket-Key"))

	// Send 101 Switching Protocols to the browser
	resp101 := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := clientConn.Write([]byte(resp101)); err != nil {
		wsRelayClose(coal, sessionID)
		return
	}
	logf("info", "WebSocket %s established via GAS relay (session %.8s…)", targetHost, sessionID)

	// done is closed by the reader goroutine when it exits, which causes
	// SetDeadline to unblock the writer's readWSFrame call.
	done := make(chan struct{})

	// Reader goroutine: VPS relay → browser
	go func() {
		defer func() {
			close(done)
			clientConn.SetDeadline(time.Now()) // unblock writer's read
		}()
		wsProxyReader(clientConn, coal, sessionID)
		// Best-effort WS close frame to the browser
		_ = writeWSFrame(clientConn, wsFrame{Fin: true, Opcode: wsOpClose}, false)
	}()

	// Writer (this goroutine): browser → VPS relay
	wsProxyWriter(clientReader, clientConn, coal, sessionID, done)

	<-done
	wsRelayClose(coal, sessionID)
}

// wsProxyReader polls the VPS relay for incoming frames and writes them to
// the browser connection. It returns when the upstream session is closed or
// a transport error occurs.
func wsProxyReader(conn net.Conn, coal *Coalescer, sessionID string) {
	for {
		frames, closed, err := wsRelayRecv(coal, sessionID, 20_000)
		if err != nil || closed {
			return
		}
		for _, f := range frames {
			// Server → client: no masking required
			if err := writeWSFrame(conn, f, false); err != nil {
				return
			}
		}
	}
}

// wsProxyWriter reads WebSocket frames from the browser and forwards them to
// the VPS relay. It returns when the browser closes the connection, sends a
// WS close frame, or done is closed (reader side exited).
func wsProxyWriter(r *bufio.Reader, conn net.Conn, coal *Coalescer, sessionID string, done <-chan struct{}) {
	for {
		// Non-blocking check: exit immediately if reader already quit
		select {
		case <-done:
			return
		default:
		}

		f, err := readWSFrame(r)
		if err != nil {
			return
		}

		switch f.Opcode {
		case wsOpClose:
			wsRelayClose(coal, sessionID)
			return
		case wsOpPing:
			// Respond directly to the browser; do not relay the ping upstream
			_ = writeWSFrame(conn, wsFrame{Fin: true, Opcode: wsOpPong, Payload: f.Payload}, false)
		default:
			if err := wsRelaySend(coal, sessionID, []wsFrame{f}); err != nil {
				return
			}
		}
	}
}
