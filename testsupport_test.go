package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA is a throwaway certificate authority used to issue client
// certificates for the tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

// newTestCA creates a self-signed certificate authority.
func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{cert: cert, key: key, pool: pool}
}

// issueClient writes a client certificate and key for the given common name
// into dir, returning their paths.
func (ca *testCA) issueClient(t *testing.T, dir, commonName string, notAfter time.Time) (string, string) {
	t.Helper()

	certPath := filepath.Join(dir, commonName+".crt")
	keyPath := filepath.Join(dir, commonName+".key")
	ca.issueClientAt(t, certPath, keyPath, commonName, notAfter)

	return certPath, keyPath
}

// issueClientAt writes a client certificate and key to explicit paths,
// replacing whatever is already there.
func (ca *testCA) issueClientAt(t *testing.T, certPath, keyPath, commonName string, notAfter time.Time) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// newEchoServer starts a TLS server that requires a client certificate and
// reports the common name it was presented, along with the Host header it
// received.
func newEchoServer(t *testing.T, ca *testCA) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		commonName := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			commonName = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("X-Presented-CN", commonName)
		w.Header().Set("X-Received-Host", r.Host)
		w.Header().Set("X-Selector-Seen", r.Header.Get("X-Client-Name"))
		w.Header().Set("X-Upstream-Close", fmt.Sprintf("%t", r.Close))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("cn=" + commonName))
	}))

	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.pool,
		MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	// Trust the certificate the test server presents, and restore the
	// previous value so tests do not leak into one another.
	previous := upstreamRootCAs
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	upstreamRootCAs = pool
	t.Cleanup(func() { upstreamRootCAs = previous })

	return server
}

// hostOf strips the scheme from a test server URL, leaving host:port.
func hostOf(server *httptest.Server) string {
	return strings.TrimPrefix(server.URL, "https://")
}
