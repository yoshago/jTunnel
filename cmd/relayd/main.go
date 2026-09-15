// Command relayd is the Relay Server: it accepts one mTLS-authenticated
// control connection from the CLI Agent, upgrades it to a Yamux session, and
// (for this step) simply echoes back whatever it reads on the first stream
// opened by the Agent, to prove end-to-end connectivity.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/hashicorp/yamux"
	"github.com/yoshago/jTunnel/internal/muxsession"
	"github.com/yoshago/jTunnel/internal/protocol"
	"github.com/yoshago/jTunnel/internal/tlsconfig"
)

// Default flag values; override via the corresponding CLI flag.
const (
	defaultAddr     = ":9090"
	defaultCAFile   = "certs/ca-cert.pem"
	defaultCertFile = "certs/server-cert.pem"
	defaultKeyFile  = "certs/server-key.pem"
)

func main() {
	addr := flag.String("addr", defaultAddr, "control listen address")
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

	registry := &tunnelRegistry{}

	// Accept loop: every inbound mTLS connection is a potential agent; each
	// one is handled on its own goroutine so multiple attempts don't block.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleAgent(conn, registry)
	}
}

// tunnelRegistry tracks the single active agent session for this MVP.
type tunnelRegistry struct {
	mu     sync.Mutex
	active *yamux.Session
}

// SetActive installs session as the active one and returns any previous
// session that was replaced, so the caller can close it.
func (r *tunnelRegistry) SetActive(session *yamux.Session) (previous *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous = r.active
	r.active = session
	return previous
}

// Clear removes session from the registry, but only if it's still the
// active one (a stale, already-replaced session disconnecting shouldn't
// wipe out a newer one).
func (r *tunnelRegistry) Clear(session *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == session {
		r.active = nil
	}
}

// IsActive reports whether any agent is currently connected.
func (r *tunnelRegistry) IsActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active != nil
}

// handleAgent runs the full lifecycle of one agent's control connection:
// handshake, mux upgrade, then relaying whatever streams it opens.
func handleAgent(conn net.Conn, registry *tunnelRegistry) {
	defer conn.Close()

	// Application-level handshake (plain JSON, pre-mux): learn who's
	// connecting and hand back a tunnel id.
	hello, err := protocol.ReadHello(conn)
	if err != nil {
		log.Printf("read hello: %v", err)
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

	// Each Accept() call yields one stream the agent opened; handle each
	// concurrently since a real session may have many in flight at once.
	for {
		stream, err := session.Accept()
		if err != nil {
			log.Printf("agent %q disconnected: %v", hello.AgentID, err)
			return
		}
		go echoStream(stream)
	}
}

// echoStream is a stand-in for real request proxying (added in a later step):
// it just bounces back whatever bytes the agent sends on this stream.
func echoStream(stream net.Conn) {
	defer stream.Close()
	if _, err := io.Copy(stream, stream); err != nil && err != io.EOF {
		log.Printf("echo stream error: %v", err)
	}
}
