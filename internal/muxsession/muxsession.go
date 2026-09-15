// Package muxsession wraps hashicorp/yamux session creation with tuned config.
package muxsession

import (
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

func config() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	return cfg
}

// NewServerSession upgrades conn to a Yamux session acting as the server side.
// Used by the Relay Server, which accepts streams opened by the Agent.
func NewServerSession(conn net.Conn) (*yamux.Session, error) {
	return yamux.Server(conn, config())
}

// NewClientSession upgrades conn to a Yamux session acting as the client side.
// Used by the CLI Agent, which opens streams towards the Relay Server.
func NewClientSession(conn net.Conn) (*yamux.Session, error) {
	return yamux.Client(conn, config())
}
