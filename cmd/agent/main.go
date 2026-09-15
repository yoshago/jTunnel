// Command agent is the CLI Agent: it dials the Relay Server over mTLS,
// performs the handshake, upgrades to a Yamux session, opens a stream,
// sends a "Ping" payload, and logs the echoed response to prove
// end-to-end connectivity.
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"time"

	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/tlsconfig"
)

// Default flag values, suitable for a relayd running on localhost; override
// via the corresponding CLI flag for anything else (e.g. a real relay host).
const (
	defaultAddr       = "127.0.0.1:9090"
	defaultServerName = "localhost"
	defaultAgentID    = "local-agent"
	defaultCAFile     = "certs/ca-cert.pem"
	defaultCertFile   = "certs/client-cert.pem"
	defaultKeyFile    = "certs/client-key.pem"
	defaultTimeout    = 10 * time.Second
)

func main() {
	addr := flag.String("addr", defaultAddr, "relay server control address")
	serverName := flag.String("server-name", defaultServerName, "expected server certificate name")
	agentID := flag.String("agent-id", defaultAgentID, "identifier reported to the relay server")
	caFile := flag.String("ca", defaultCAFile, "path to CA certificate")
	certFile := flag.String("cert", defaultCertFile, "path to client certificate")
	keyFile := flag.String("key", defaultKeyFile, "path to client private key")
	timeout := flag.Duration("timeout", defaultTimeout, "timeout for dialing and for the request/response exchange")
	flag.Parse()

	// Step 1: build the mTLS client config - presents our client cert and
	// verifies the relay's server cert against the shared CA.
	tlsCfg, err := tlsconfig.LoadClientTLSConfig(*caFile, *certFile, *keyFile, *serverName)
	if err != nil {
		log.Fatalf("load client tls config: %v", err)
	}

	// Step 2: open the raw mTLS connection to the relay's control port, bounded
	// by timeout so a stuck network path doesn't hang the agent forever.
	dialer := &net.Dialer{Timeout: *timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", *addr, tlsCfg)
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer conn.Close()

	// Step 3: application-level handshake (plain JSON, pre-mux) - identify
	// ourselves and receive the tunnel id the relay assigned us.
	if err := protocol.WriteHello(conn, protocol.Hello{AgentID: *agentID}); err != nil {
		log.Fatalf("write hello: %v", err)
	}
	ack, err := protocol.ReadAck(conn)
	if err != nil {
		log.Fatalf("read ack: %v", err)
	}
	log.Printf("connected, assigned tunnel id %q", ack.TunnelID)

	// Step 4: upgrade the single TCP connection to a Yamux session, which lets
	// many independent logical streams share it concurrently.
	session, err := muxsession.NewClientSession(conn)
	if err != nil {
		log.Fatalf("new client session: %v", err)
	}
	defer session.Close()

	// Step 5: open one stream over the session (like opening a new virtual
	// connection) to prove the tunnel works end-to-end.
	stream, err := session.Open()
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	// Bound the whole request/response exchange so a stalled relay can't hang
	// the write or the io.ReadFull below indefinitely.
	if err := stream.SetDeadline(time.Now().Add(*timeout)); err != nil {
		log.Fatalf("set stream deadline: %v", err)
	}

	payload := []byte("Ping")
	if _, err := stream.Write(payload); err != nil {
		log.Fatalf("write payload: %v", err)
	}

	// The relay's echoStream handler (see cmd/relayd) sends the same bytes back.
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, resp); err != nil {
		log.Fatalf("read echo: %v", err)
	}

	log.Printf("sent %q, received echo %q", payload, resp)
}
