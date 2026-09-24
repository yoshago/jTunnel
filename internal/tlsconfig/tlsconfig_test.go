package tlsconfig

import (
	"net"
	"testing"

	"github.com/yoshago/jTunnel/internal/testutil"
)

func TestLoadTLSConfigs(t *testing.T) {
	certs := testutil.GenerateCerts(t, t.TempDir())

	server, err := LoadServerTLSConfig(certs.CAFile, certs.ServerCert, certs.ServerKey)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	if server.ClientAuth == 0 || len(server.Certificates) != 1 {
		t.Fatalf("server config does not require a client certificate")
	}

	client, err := LoadClientTLSConfig(certs.CAFile, certs.ClientCert, certs.ClientKey, "localhost")
	if err != nil {
		t.Fatalf("LoadClientTLSConfig: %v", err)
	}
	if len(client.Certificates) != 1 || client.ServerName != "localhost" {
		t.Fatalf("client config is incomplete")
	}
}

func TestLoadTLSConfigsRejectMissingFiles(t *testing.T) {
	if _, err := LoadServerTLSConfig("missing-ca", "missing-cert", "missing-key"); err == nil {
		t.Fatal("expected missing server files to fail")
	}
	if _, err := LoadClientTLSConfig("missing-ca", "missing-cert", "missing-key", "localhost"); err == nil {
		t.Fatal("expected missing client files to fail")
	}
}

func TestVerifyPeerCommonNameRejectsNonTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := VerifyPeerCommonName(client, "agent"); err == nil {
		t.Fatal("expected non-TLS connection to be rejected")
	}
}
