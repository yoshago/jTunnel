// Command relayd is the Relay Server: it accepts one mTLS-authenticated
// control connection from the CLI Agent, upgrades it to a Yamux session, and
// runs a public HTTP proxy that forwards public requests to the Agent over
// that session (the L7 application proxy).
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/relayproxy"
	"github.com/yoshago/jTunnel/internal/tlsconfig"
)

// Default flag values; override via the corresponding CLI flag.
const (
	defaultAddr        = ":9090"
	defaultPublicAddr  = ":8080"
	defaultCAFile      = "certs/ca-cert.pem"
	defaultCertFile    = "certs/server-cert.pem"
	defaultKeyFile     = "certs/server-key.pem"
	proxyStreamTimeout = 30 * time.Second
)

func main() {
	addr := flag.String("addr", defaultAddr, "control listen address")
	publicAddr := flag.String("public-addr", defaultPublicAddr, "public HTTP proxy listen address")
	caFile := flag.String("ca", defaultCAFile, "path to CA certificate")
	certFile := flag.String("cert", defaultCertFile, "path to server certificate")
	keyFile := flag.String("key", defaultKeyFile, "path to server private key")
	flag.Parse()

	// Build the mTLS server config - requires and verifies an agent's client
	// cert against the shared CA before any connection is accepted.
	tlsCfg, err := tlsconfig.LoadServerTLSConfig(*caFile, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("load server tls config: %v", err)
	}

	ln, err := tls.Listen("tcp", *addr, tlsCfg)
	if err != nil {
		log.Fatalf("listen on %s: %v", *addr, err)
	}
	log.Printf("relayd listening on %s (mTLS)", *addr)

	registry := &relayproxy.Registry{}

	// The public HTTP proxy runs alongside the mTLS control listener: each
	// request it receives is forwarded to the currently connected agent.
	go func() {
		log.Printf("relayd public HTTP proxy listening on %s", *publicAddr)
		if err := http.ListenAndServe(*publicAddr, relayproxy.NewHandler(registry, proxyStreamTimeout)); err != nil {
			log.Fatalf("public http server: %v", err)
		}
	}()

	// Accept loop: every inbound mTLS connection is a potential agent; each
	// one is handled on its own goroutine so multiple attempts don't block.
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Printf("listener closed: %v", err)
				return
			}
			log.Printf("accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handleAgent(conn, registry)
	}
}

// handleAgent runs the full lifecycle of one agent's control connection:
// handshake, mux upgrade, then relaying whatever streams it opens.
func handleAgent(conn net.Conn, registry *relayproxy.Registry) {
	defer conn.Close()

	// Application-level handshake (plain JSON, pre-mux): learn who's
	// connecting and hand back a tunnel id.
	hello, err := protocol.ReadHello(conn)
	if err != nil {
		log.Printf("read hello: %v", err)
		return
	}

	// The AgentID is caller-supplied and must not be trusted on its own: bind
	// it to the identity proven by the client's mTLS certificate.
	if err := tlsconfig.VerifyPeerCommonName(conn, hello.AgentID); err != nil {
		log.Printf("reject agent %q: %v", hello.AgentID, err)
		return
	}

	tunnelID := fmt.Sprintf("tunnel-%s", hello.AgentID)
	if err := protocol.WriteAck(conn, protocol.Ack{TunnelID: tunnelID}); err != nil {
		log.Printf("write ack: %v", err)
		return
	}

	// Upgrade the same TCP connection to a Yamux session, so the agent can
	// open many independent streams over it later (one per tunneled request).
	session, err := muxsession.NewServerSession(conn)
	if err != nil {
		log.Printf("new server session: %v", err)
		return
	}
	defer session.Close()
	defer registry.Clear(session)

	if previous := registry.SetActive(session); previous != nil {
		previous.Close() // MVP: single active tunnel, replace any previous one.
	}

	log.Printf("agent %q connected, assigned %s (tunnel active: %v)", hello.AgentID, tunnelID, registry.IsActive())

	// In the L7 model the Relay opens streams towards the Agent (one per
	// public HTTP request via relayproxy.NewHandler), so there's nothing to
	// accept here; just block until the session goes down.
	<-session.CloseChan()
	log.Printf("agent %q disconnected", hello.AgentID)
}
