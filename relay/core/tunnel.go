package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// tunnelRelayPath is the path suffix expected on VPS relay URLs.
const tunnelRelayPath = "/relay"

// tunnelPath is the path exposed by the VPS relay for raw TCP tunneling.
const tunnelPath = "/tunnel"

// isVPSRelayURL reports whether rawURL looks like a VPS relay endpoint
// (as opposed to a Google Apps Script URL). VPS URLs have a custom host and
// end with /relay; GAS URLs always contain "script.google".
func isVPSRelayURL(rawURL string) bool {
	if strings.Contains(rawURL, "script.google") {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.HasSuffix(u.Path, tunnelRelayPath)
}

// deriveTunnelURL converts a VPS relay URL (ending in /relay) to its tunnel
// sibling (ending in /tunnel). Returns "" if rawURL is not a VPS relay URL.
func deriveTunnelURL(rawURL string) string {
	if !isVPSRelayURL(rawURL) {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	base := strings.TrimSuffix(u.Path, tunnelRelayPath)
	u.Path = base + tunnelPath
	return u.String()
}

// DialTunnel opens a raw TCP connection to targetHost (host:port) through the
// VPS relay's /tunnel endpoint. It uses an HTTP/1.1 Upgrade handshake so that
// HTTP/2 (which does not support Upgrade) is never negotiated.
//
// The returned net.Conn carries raw bytes to/from targetHost. The caller is
// responsible for closing it.
func DialTunnel(tunnelURL, targetHost, authKey string) (net.Conn, error) {
	u, err := url.Parse(tunnelURL)
	if err != nil {
		return nil, fmt.Errorf("dial tunnel: bad tunnel URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	// Dial raw TCP — we send the HTTP/1.1 upgrade ourselves to guarantee
	// HTTP/1.1 is used (http.Client would negotiate HTTP/2 via TLS ALPN).
	var conn net.Conn
	conn, err = net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tunnel: tcp dial %s: %w", addr, err)
	}

	if u.Scheme == "https" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			// Do NOT advertise h2 — we need HTTP/1.1 for Upgrade to work.
			NextProtos: []string{"http/1.1"},
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("dial tunnel: TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// Send HTTP/1.1 upgrade request.
	req, err := http.NewRequest(http.MethodGet, tunnelURL, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("dial tunnel: build request: %w", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp-tunnel")
	req.Header.Set("X-Tunnel-Host", targetHost)
	if authKey != "" {
		req.Header.Set("X-Relay-Key", authKey)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("dial tunnel: write request: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("dial tunnel: read response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("dial tunnel: expected 101, got %d", resp.StatusCode)
	}

	// If bufio.Reader has buffered bytes beyond the HTTP response we must
	// drain them before handing conn back; wrap if needed.
	if reader.Buffered() > 0 {
		return &bufferedTunnelConn{Conn: conn, r: reader}, nil
	}
	return conn, nil
}

// bufferedTunnelConn wraps a net.Conn where the bufio.Reader may have already
// consumed bytes beyond the HTTP response. Reads drain the buffer first.
type bufferedTunnelConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedTunnelConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
