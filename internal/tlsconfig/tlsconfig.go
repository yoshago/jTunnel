// Package tlsconfig builds mutual-TLS configs for the relay/agent control channel.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// LoadServerTLSConfig builds a server-side tls.Config that requires and verifies
// a client certificate signed by the CA in caFile.
func LoadServerTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caPool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// LoadClientTLSConfig builds a client-side tls.Config that presents a client
// certificate and verifies the server certificate against the CA in caFile.
// serverName must match the name (or SAN) baked into the server certificate.
func LoadClientTLSConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	caPool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// VerifyPeerCommonName checks that conn is a TLS connection whose verified
// peer (client) certificate has the given CommonName. It must be called only
// after the handshake has completed (e.g. after the first Read/Write on
// conn), and is the source of truth for peer identity: callers must not
// trust any self-reported identity (such as an application-level AgentID)
// without this check.
func VerifyPeerCommonName(conn net.Conn, expected string) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("connection is not TLS")
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no verified peer certificate")
	}

	if cn := state.PeerCertificates[0].Subject.CommonName; cn != expected {
		return fmt.Errorf("peer certificate identity %q does not match claimed identity %q", cn, expected)
	}
	return nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return pool, nil
}
