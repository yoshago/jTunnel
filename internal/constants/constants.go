// Package constants contains shared operational defaults and limits.
package constants

import "time"

const (
	DefaultAgentAddr        = "127.0.0.1:9090"
	DefaultRelayAddr        = ":9090"
	DefaultPublicAddr       = ":8080"
	DefaultServerName       = "localhost"
	DefaultAgentID          = "agent"
	DefaultCAFile           = "certs/ca-cert.pem"
	DefaultClientCertFile   = "certs/client-cert.pem"
	DefaultClientKeyFile    = "certs/client-key.pem"
	DefaultServerCertFile   = "certs/server-cert.pem"
	DefaultServerKeyFile    = "certs/server-key.pem"
	DefaultTarget           = "http://127.0.0.1:5678"
	AgentDialTimeout        = 10 * time.Second
	HandshakeTimeout        = 5 * time.Second
	MaxHandshakeSize        = 4096
	ProxyStreamTimeout      = 30 * time.Second
	PublicReadHeaderTimeout = 10 * time.Second
	PublicIdleTimeout       = 120 * time.Second
	YamuxKeepAliveInterval  = 30 * time.Second
	YamuxWriteTimeout       = 10 * time.Second
	TunnelIDPrefix          = "tunnel-"
)
