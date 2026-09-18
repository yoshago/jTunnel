// Command agent is the CLI Agent: it dials the Relay Server over mTLS,
// performs the handshake, upgrades to a Yamux session, and then accepts
// streams opened by the Relay, forwarding each one as an HTTP request to a
// local target (the Local Forwarder half of the L7 application proxy).
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/yoshago/jTunnel/internal/agentproxy"
	"github.com/yoshago/jTunnel/internal/constants"
	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/tlsconfig"
)

func main() {
	addr := flag.String("addr", constants.DefaultAgentAddr, "relay server control address")
	serverName := flag.String("server-name", constants.DefaultServerName, "expected server certificate name")
	agentID := flag.String("agent-id", constants.DefaultAgentID, "identifier reported to the relay server")
	caFile := flag.String("ca", constants.DefaultCAFile, "path to CA certificate")
	certFile := flag.String("cert", constants.DefaultClientCertFile, "path to client certificate")
	keyFile := flag.String("key", constants.DefaultClientKeyFile, "path to client private key")
	timeout := flag.Duration("timeout", constants.AgentDialTimeout, "timeout for dialing and for the handshake")
	target := flag.String("target", constants.DefaultTarget, "local target base URL to forward tunneled requests to")
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

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: *timeout}).DialContext,
			ResponseHeaderTimeout: *timeout,
			TLSHandshakeTimeout:   *timeout,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	log.Printf("forwarding tunneled requests to %s", *target)

	// Each Accept() call yields one stream the Relay opened for a single
	// public HTTP request; handle each concurrently since several may be
	// in flight at once.
	for {
		stream, err := session.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				log.Printf("session closed: %v", err)
				return
			}
			log.Printf("accept stream: %v", err)
			return
		}
		go agentproxy.HandleStream(stream, *target, client)
	}
}
