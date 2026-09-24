// Package testutil provides shared test helpers, such as throwaway mTLS
// certificate generation, for use across internal package tests.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Certs holds the file paths of a generated dev CA plus a server/client
// cert+key pair signed by it.
type Certs struct {
	CAFile     string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// GenerateCerts creates a throwaway CA, a server cert (SAN: 127.0.0.1,
// localhost), and a client cert, all written as PEM files under dir.
func GenerateCerts(t *testing.T, dir string) Certs {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caFile := filepath.Join(dir, "ca-cert.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)

	serverCert := filepath.Join(dir, "server-cert.pem")
	serverKey := filepath.Join(dir, "server-key.pem")
	issueLeaf(t, caTemplate, caKey, leafOptions{
		cn:          "relayd",
		sanIPsOrDNS: []string{"127.0.0.1", "localhost"},
		keyUsage:    x509.ExtKeyUsageServerAuth,
		certPath:    serverCert,
		keyPath:     serverKey,
	})

	clientCert := filepath.Join(dir, "client-cert.pem")
	clientKey := filepath.Join(dir, "client-key.pem")
	issueLeaf(t, caTemplate, caKey, leafOptions{
		cn:       "agent",
		keyUsage: x509.ExtKeyUsageClientAuth,
		certPath: clientCert,
		keyPath:  clientKey,
	})

	return Certs{
		CAFile:     caFile,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}
}

type leafOptions struct {
	cn          string
	sanIPsOrDNS []string
	keyUsage    x509.ExtKeyUsage
	certPath    string
	keyPath     string
}

func issueLeaf(t *testing.T, caTemplate *x509.Certificate, caKey *rsa.PrivateKey, opts leafOptions) {
	t.Helper()

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: opts.cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{opts.keyUsage},
	}
	for _, s := range opts.sanIPsOrDNS {
		if ip := net.ParseIP(s); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, s)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert for %s: %v", opts.cn, err)
	}

	writePEM(t, opts.certPath, "CERTIFICATE", der)

	keyDER := x509.MarshalPKCS1PrivateKey(leafKey)
	writePEM(t, opts.keyPath, "RSA PRIVATE KEY", keyDER)
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
}
