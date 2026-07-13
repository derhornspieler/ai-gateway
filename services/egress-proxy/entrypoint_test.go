package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	directory := t.TempDir()
	ca := filepath.Join(directory, "vendor-ca.pem")
	writeTestCA(t, ca)
	config := filepath.Join(directory, "envoy.yaml")
	text := strings.Repeat("typed_config:\n  @type: type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext\n  common_tls_context:\n    validation_context:\n      trusted_ca: { filename: "+ca+" }\n", 2)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsMissingAndSystemBundles(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "envoy.yaml")
	if err := os.WriteFile(config, []byte("UpstreamTlsContext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(config); err == nil {
		t.Fatal("expected missing trusted_ca to fail")
	}
	system := "UpstreamTlsContext\ntrusted_ca: { filename: /etc/ssl/certs/ca-certificates.crt }\n"
	if err := os.WriteFile(config, []byte(system), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(config); err == nil {
		t.Fatal("expected system bundle to fail")
	}
}

func TestRejectsOverrides(t *testing.T) {
	for _, argument := range []string{"-c", "--config-path", "--config-yaml=x"} {
		if err := rejectConfigOverrides([]string{argument}); err == nil {
			t.Fatalf("expected %s to fail", argument)
		}
	}
}

func writeTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
