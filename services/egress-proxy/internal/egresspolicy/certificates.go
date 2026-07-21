package egresspolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// validateBundle requires the exact reviewed bytes and certificate sequence.
// The byte hash catches formatting or extra-data changes. DER fingerprints
// identify each certificate independently.
func validateBundle(
	content []byte,
	expectedBundleSHA256 string,
	expectedFingerprints []string,
	now time.Time,
) error {
	if sha256Hex(content) != expectedBundleSHA256 {
		return errors.New("CA bundle SHA-256 does not match the reviewed catalog")
	}
	if len(expectedFingerprints) == 0 {
		return errors.New("CA bundle has no reviewed certificate fingerprints")
	}
	remaining := content
	actualFingerprints := make([]string, 0, len(expectedFingerprints))
	seen := make(map[string]struct{}, len(expectedFingerprints))
	for {
		remaining = bytes.TrimSpace(remaining)
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("CA bundle contains text outside certificate PEM blocks")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return errors.New("CA bundle contains malformed PEM")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("CA bundle contains a non-certificate PEM block or PEM headers")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("CA bundle contains invalid certificate DER")
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return errors.New("CA bundle contains a certificate without valid CA constraints")
		}
		if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("CA bundle contains a CA that cannot sign certificates")
		}
		if now.Before(certificate.NotBefore) {
			return fmt.Errorf("CA certificate %q is not valid yet", certificate.Subject.String())
		}
		if !now.Before(certificate.NotAfter) {
			return fmt.Errorf("CA certificate %q is expired", certificate.Subject.String())
		}
		digest := sha256.Sum256(certificate.Raw)
		fingerprint := hex.EncodeToString(digest[:])
		if _, duplicate := seen[fingerprint]; duplicate {
			return errors.New("CA bundle contains a duplicate certificate")
		}
		seen[fingerprint] = struct{}{}
		actualFingerprints = append(actualFingerprints, fingerprint)
		remaining = rest
	}
	if !equalStrings(actualFingerprints, expectedFingerprints) {
		return fmt.Errorf(
			"CA certificate fingerprints do not match the reviewed order: got %v",
			actualFingerprints,
		)
	}
	return nil
}
