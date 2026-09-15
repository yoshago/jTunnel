// Package protocol defines the control-channel handshake exchanged between
// the CLI Agent and the Relay Server before the connection is upgraded to a
// Yamux multiplexed session.
package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	maxHandshakeSize = 4096
	handshakeTimeout = 5 * time.Second
)

// Hello is sent by the Agent right after the mTLS handshake completes.
type Hello struct {
	AgentID string `json:"agent_id"`
}

// Ack is sent by the Relay Server in response to a Hello.
type Ack struct {
	TunnelID string `json:"tunnel_id"`
}

// WriteHello sends a newline-terminated JSON Hello over conn.
func WriteHello(conn net.Conn, hello Hello) error {
	return writeJSONLine(conn, hello)
}

// ReadHello reads a newline-terminated JSON Hello from conn.
func ReadHello(conn net.Conn) (Hello, error) {
	var hello Hello
	err := readJSONLine(conn, &hello)
	return hello, err
}

// WriteAck sends a newline-terminated JSON Ack over conn.
func WriteAck(conn net.Conn, ack Ack) error {
	return writeJSONLine(conn, ack)
}

// ReadAck reads a newline-terminated JSON Ack from conn.
func ReadAck(conn net.Conn) (Ack, error) {
	var ack Ack
	err := readJSONLine(conn, &ack)
	return ack, err
}

func writeJSONLine(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal handshake message: %w", err)
	}
	data = append(data, '\n')
	if err := conn.SetWriteDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer conn.SetWriteDeadline(time.Time{})
	_, err = conn.Write(data)
	return err
}

// readJSONLine reads one byte at a time up to '\n': a bufio.Reader would risk
// buffering bytes belonging to the Yamux session that starts right after this call.
// A deadline and a size cap guard against a stalled or malicious peer.
func readJSONLine(conn net.Conn, v interface{}) error {
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	limited := io.LimitReader(conn, maxHandshakeSize)
	var buf bytes.Buffer
	one := make([]byte, 1)
	for {
		n, err := limited.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			buf.WriteByte(one[0])
		}
		if err != nil {
			if err == io.EOF && buf.Len() >= maxHandshakeSize {
				return fmt.Errorf("handshake message exceeds %d bytes", maxHandshakeSize)
			}
			return fmt.Errorf("read handshake message: %w", err)
		}
	}
	return json.Unmarshal(buf.Bytes(), v)
}
