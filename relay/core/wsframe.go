package core

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

// WebSocket opcodes (RFC 6455 §5.2).
const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

const wsMaxPayload = 16 << 20 // 16 MB

// wsFrame is a decoded WebSocket frame.
type wsFrame struct {
	Fin     bool
	Opcode  byte
	Payload []byte
}

// readWSFrame reads one WebSocket frame from r.
// It handles both masked (client→server) and unmasked (server→client) frames.
func readWSFrame(r io.Reader) (wsFrame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return wsFrame{}, fmt.Errorf("ws header: %w", err)
	}

	fin := (hdr[0] & 0x80) != 0
	op := hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	payLen := int(hdr[1] & 0x7F)

	switch payLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, fmt.Errorf("ws ext16: %w", err)
		}
		payLen = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, fmt.Errorf("ws ext64: %w", err)
		}
		n := binary.BigEndian.Uint64(ext[:])
		if n > wsMaxPayload {
			return wsFrame{}, fmt.Errorf("ws payload too large: %d", n)
		}
		payLen = int(n)
	}
	if payLen > wsMaxPayload {
		return wsFrame{}, fmt.Errorf("ws payload too large: %d", payLen)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return wsFrame{}, fmt.Errorf("ws mask: %w", err)
		}
	}

	payload := make([]byte, payLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return wsFrame{}, fmt.Errorf("ws payload: %w", err)
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return wsFrame{Fin: fin, Opcode: op, Payload: payload}, nil
}

// writeWSFrame writes a WebSocket frame to w.
// If doMask is true the payload is masked with a fresh random key (required
// for client→server frames per RFC 6455 §5.3).
func writeWSFrame(w io.Writer, f wsFrame, doMask bool) error {
	b0 := f.Opcode
	if f.Fin {
		b0 |= 0x80
	}
	payLen := len(f.Payload)

	var hdr []byte
	hdr = append(hdr, b0)

	maskBit := byte(0)
	if doMask {
		maskBit = 0x80
	}
	switch {
	case payLen < 126:
		hdr = append(hdr, maskBit|byte(payLen))
	case payLen < 65536:
		hdr = append(hdr, maskBit|126, byte(payLen>>8), byte(payLen))
	default:
		hdr = append(hdr, maskBit|127,
			0, 0, 0, 0,
			byte(payLen>>24), byte(payLen>>16), byte(payLen>>8), byte(payLen))
	}

	if doMask {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return fmt.Errorf("ws mask key: %w", err)
		}
		hdr = append(hdr, key[:]...)
		masked := make([]byte, payLen)
		for i, b := range f.Payload {
			masked[i] = b ^ key[i%4]
		}
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		_, err := w.Write(masked)
		return err
	}

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}

// wsGUID is the RFC 6455 magic GUID used in Sec-WebSocket-Accept computation.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsComputeAccept computes the Sec-WebSocket-Accept value for a given
// Sec-WebSocket-Key, as specified in RFC 6455 §4.2.2.
func wsComputeAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
