package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/relayproxy"
	"github.com/yoshago/jTunnel/internal/testutil"
	"github.com/yoshago/jTunnel/internal/tlsconfig"
)

func TestHandleAgentAuthenticatesAndRegistersSession(t *testing.T) {
	certs := testutil.GenerateCerts(t, t.TempDir())
	serverConfig, err := tlsconfig.LoadServerTLSConfig(certs.CAFile, certs.ServerCert, certs.ServerKey)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	clientConfig, err := tlsconfig.LoadClientTLSConfig(certs.CAFile, certs.ClientCert, certs.ClientKey, "localhost")
	if err != nil {
		t.Fatalf("load client config: %v", err)
	}

	serverRaw, clientRaw := net.Pipe()
	serverConn := tls.Server(serverRaw, serverConfig)
	clientConn := tls.Client(clientRaw, clientConfig)
	registry := &relayproxy.Registry{}
	handleDone := make(chan struct{})
	go func() {
		handleAgent(serverConn, registry)
		close(handleDone)
	}()

	if err := protocol.WriteHello(clientConn, protocol.Hello{AgentID: "agent"}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	ack, err := protocol.ReadAck(clientConn)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.TunnelID != "tunnel-agent" {
		t.Fatalf("unexpected tunnel id %q", ack.TunnelID)
	}

	session, err := muxsession.NewClientSession(clientConn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	registrationDeadline := time.Now().Add(time.Second)
	for !registry.IsActive() {
		if time.Now().After(registrationDeadline) {
			t.Fatal("timed out waiting for agent session to become active")
		}
		time.Sleep(time.Millisecond)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("close client session: %v", err)
	}
	select {
	case <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("handleAgent did not return after session close")
	}
}
