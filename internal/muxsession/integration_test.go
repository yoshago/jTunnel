package muxsession_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/testutil"
	"github.com/yoshago/jTunnel/internal/tlsconfig"
)

// TestHandshakeAndMuxRoundTrip stands up an in-memory mTLS listener (simulating
// relayd), dials it (simulating the agent), performs the Hello/Ack handshake,
// upgrades both ends to Yamux sessions, and verifies an echoed payload round-trips.
func TestHandshakeAndMuxRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certs := testutil.GenerateCerts(t, dir)

	serverTLSCfg, err := tlsconfig.LoadServerTLSConfig(certs.CAFile, certs.ServerCert, certs.ServerKey)
	if err != nil {
		t.Fatalf("load server tls config: %v", err)
	}
	clientTLSCfg, err := tlsconfig.LoadClientTLSConfig(certs.CAFile, certs.ClientCert, certs.ClientKey, "localhost")
	if err != nil {
		t.Fatalf("load client tls config: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	payload := []byte("Ping")

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- runServerSide(ln, len(payload))
	}()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	dialer := &tls.Dialer{Config: clientTLSCfg}
	conn, err := dialer.DialContext(dialCtx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := protocol.WriteHello(conn, protocol.Hello{AgentID: "test-agent"}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	ack, err := protocol.ReadAck(conn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.TunnelID == "" {
		t.Fatalf("expected non-empty tunnel id in ack")
	}

	clientSession, err := muxsession.NewClientSession(conn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	defer clientSession.Close()

	stream, err := clientSession.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, resp); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(payload, resp) {
		t.Fatalf("expected echo %q, got %q", payload, resp)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side error: %v", err)
	}
}

// runServerSide accepts a single connection, performs the handshake, upgrades
// to a Yamux server session, and echoes one stream's payload back.
func runServerSide(ln net.Listener, payloadLen int) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := protocol.ReadHello(conn); err != nil {
		return err
	}
	if err := protocol.WriteAck(conn, protocol.Ack{TunnelID: "test-tunnel"}); err != nil {
		return err
	}

	session, err := muxsession.NewServerSession(conn)
	if err != nil {
		return err
	}
	defer session.Close()

	stream, err := session.Accept()
	if err != nil {
		return err
	}
	defer stream.Close()

	// The client may write the payload across multiple frames/reads, so read
	// exactly the expected length before echoing it back.
	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return err
	}
	_, err = stream.Write(buf)
	return err
}
