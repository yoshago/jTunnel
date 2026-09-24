package protocol

import (
	"net"
	"strings"
	"testing"

	"github.com/yoshago/jTunnel/internal/constants"
)

func TestHandshakeRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverErr := make(chan error, 1)
	go func() {
		hello, err := ReadHello(server)
		if err == nil && hello.AgentID != "test-agent" {
			serverErr <- &unexpectedValueError{field: "agent id", want: "test-agent", got: hello.AgentID}
			return
		}
		serverErr <- err
	}()

	if err := WriteHello(client, Hello{AgentID: "test-agent"}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("read hello: %v", err)
	}
}

func TestReadHelloRejectsMalformedJSON(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("{not-json}\n"))
		writeErr <- err
	}()

	if _, err := ReadHello(server); err == nil {
		t.Fatal("expected malformed JSON to be rejected")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write malformed hello: %v", err)
	}
}

func TestReadHelloRejectsOversizedMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte(strings.Repeat("x", constants.MaxHandshakeSize)))
		writeErr <- err
	}()

	if _, err := ReadHello(server); err == nil {
		t.Fatal("expected oversized hello to be rejected")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write oversized hello: %v", err)
	}
}

type unexpectedValueError struct {
	field string
	want  string
	got   string
}

func (e *unexpectedValueError) Error() string {
	return e.field + ": want " + e.want + ", got " + e.got
}
