package muxsession_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yoshago/jTunnel/internal/agentproxy"
	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/relayproxy"
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

// TestL7HTTPProxyEndToEnd wires up the full request path: a mock local HTTP
// server (standing in for n8n), the Relay's mTLS control listener plus its
// public HTTP proxy, and an Agent connecting to the Relay and forwarding
// tunneled requests to the mock server. It then performs a real HTTP GET
// against the Relay's public port and asserts the body round-trips.
func TestL7HTTPProxyEndToEnd(t *testing.T) {
	wantBody := `{"status":"ok","source":"mock-n8n"}`

	// 1. Mock local HTTP server, representing n8n.
	localServer := httptestServer(t, wantBody)
	defer localServer.Close()

	// 2. Relay: mTLS control listener + public HTTP proxy, sharing a registry.
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

	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSCfg)
	if err != nil {
		t.Fatalf("listen control: %v", err)
	}
	defer controlLn.Close()

	registry := &relayproxy.Registry{}
	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen public: %v", err)
	}
	defer publicLn.Close()

	publicServer := &http.Server{Handler: relayproxy.NewHandler(registry, 5*time.Second)}
	go publicServer.Serve(publicLn)
	defer publicServer.Close()

	go acceptRelaySession(controlLn, registry)

	// 3. Agent: dials the Relay, upgrades to Yamux, and forwards accepted
	// streams to the mock local server.
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	dialer := &tls.Dialer{Config: clientTLSCfg}
	agentConn, err := dialer.DialContext(dialCtx, "tcp", controlLn.Addr().String())
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer agentConn.Close()

	if err := protocol.WriteHello(agentConn, protocol.Hello{AgentID: "test-agent"}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, err := protocol.ReadAck(agentConn); err != nil {
		t.Fatalf("read ack: %v", err)
	}

	agentSession, err := muxsession.NewClientSession(agentConn)
	if err != nil {
		t.Fatalf("agent new client session: %v", err)
	}
	defer agentSession.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	go func() {
		for {
			stream, err := agentSession.Accept()
			if err != nil {
				return
			}
			go agentproxy.HandleStream(stream, localServer.URL, httpClient)
		}
	}()

	// Wait for the relay to register the agent's session before issuing the
	// public request, since registration happens asynchronously.
	deadline := time.Now().Add(5 * time.Second)
	for !registry.IsActive() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for agent session to register")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 4. Perform the real public HTTP GET and assert the body round-trips.
	resp, err := http.Get(fmt.Sprintf("http://%s/webhook/test", publicLn.Addr().String()))
	if err != nil {
		t.Fatalf("public GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(gotBody) != wantBody {
		t.Fatalf("expected body %q, got %q", wantBody, gotBody)
	}

	// acceptRelaySession blocks until the session closes, which only happens
	// when agentConn is closed by the deferred cleanup above; nothing more to
	// wait on here.
}

// acceptRelaySession performs the Relay's side of a single agent connection:
// handshake, Yamux upgrade, and registering the session as active until the
// connection closes.
func acceptRelaySession(ln net.Listener, registry *relayproxy.Registry) error {
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
	defer registry.Clear(session)
	registry.SetActive(session)

	<-session.CloseChan()
	return nil
}

// httptestServer starts a minimal local HTTP server (standing in for n8n)
// that always returns body as a JSON response.
func httptestServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}
