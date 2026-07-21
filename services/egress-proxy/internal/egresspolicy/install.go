package egresspolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ValidateInstallation checks one complete, immutable policy installation.
// The expected digest is compiled into the launcher. The config digest binds
// the reviewed routes, host rewrites, SNI, exact SANs, and CA paths generated
// at build time.
func ValidateInstallation(
	paths InstallPaths,
	expectedPolicySHA256 string,
	now time.Time,
) (Receipt, error) {
	if !validSHA256(expectedPolicySHA256) {
		return Receipt{}, errors.New("compiled egress-policy SHA-256 is missing or malformed")
	}
	for name, path := range map[string]string{
		"policy": paths.Policy, "policy digest": paths.PolicyDigest,
		"receipt": paths.Receipt, "config": paths.Config, "certificate directory": paths.CertDir,
	} {
		if !filepath.IsAbs(path) {
			return Receipt{}, fmt.Errorf("%s path must be absolute", name)
		}
	}

	digestBytes, err := readRegularBounded(paths.PolicyDigest, 256)
	if err != nil {
		return Receipt{}, fmt.Errorf("read egress-policy digest: %w", err)
	}
	if !bytes.Equal(digestBytes, []byte(expectedPolicySHA256+"\n")) {
		return Receipt{}, errors.New("egress-policy digest file does not match the compiled digest")
	}

	policyBytes, err := readRegularBounded(paths.Policy, maxPolicyBytes)
	if err != nil {
		return Receipt{}, fmt.Errorf("read egress policy: %w", err)
	}
	if sha256Hex(policyBytes) != expectedPolicySHA256 {
		return Receipt{}, errors.New("egress-policy bytes do not match the compiled digest")
	}
	var policy RuntimePolicy
	if err := decodeStrictJSON(policyBytes, &policy); err != nil {
		return Receipt{}, fmt.Errorf("decode egress policy: %w", err)
	}
	canonicalPolicy, err := CanonicalPolicyBytes(policy)
	if err != nil {
		return Receipt{}, fmt.Errorf("validate egress policy: %w", err)
	}
	if !bytes.Equal(policyBytes, canonicalPolicy) {
		return Receipt{}, errors.New("egress policy is not canonical JSON")
	}

	configBytes, err := readRegularBounded(paths.Config, maxConfigBytes)
	if err != nil {
		return Receipt{}, fmt.Errorf("read Envoy config: %w", err)
	}
	if sha256Hex(configBytes) != policy.EnvoyConfigSHA256 {
		return Receipt{}, errors.New("Envoy config does not match the immutable policy digest")
	}

	receipt := Receipt{
		SchemaVersion:      PolicySchemaVersion,
		EgressPolicySHA256: expectedPolicySHA256,
		EnvoyConfigSHA256:  policy.EnvoyConfigSHA256,
		SelectedProviders:  append([]string(nil), policy.SelectedProviders...),
		Providers:          append([]RuntimeProvider(nil), policy.Providers...),
	}
	if err := validateReceiptFile(paths.Receipt, receipt); err != nil {
		return Receipt{}, err
	}
	if err := validateCertificateDirectory(paths.CertDir, policy.Providers, now); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func validateReceiptFile(path string, expected Receipt) error {
	content, err := readRegularBounded(path, maxPolicyBytes)
	if err != nil {
		return fmt.Errorf("read egress-policy receipt: %w", err)
	}
	var receipt Receipt
	if err := decodeStrictJSON(content, &receipt); err != nil {
		return fmt.Errorf("decode egress-policy receipt: %w", err)
	}
	canonical, err := CanonicalReceiptBytes(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, canonical) {
		return errors.New("egress-policy receipt does not match the installed policy")
	}
	return nil
}

func validateCertificateDirectory(
	path string,
	providers []RuntimeProvider,
	now time.Time,
) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read CA directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("CA path is not a real directory")
	}
	expected := make(map[string]RuntimeProvider, len(providers))
	for _, provider := range providers {
		expected[provider.CAFile] = provider
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read CA directory: %w", err)
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("CA directory contains %d entries; policy requires %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		provider, found := expected[entry.Name()]
		if !found {
			return fmt.Errorf("CA directory contains unexpected entry %q", entry.Name())
		}
		bundlePath := filepath.Join(path, entry.Name())
		bundle, err := readRegularBounded(bundlePath, maxBundleBytes)
		if err != nil {
			return fmt.Errorf("read provider %q CA bundle: %w", provider.Name, err)
		}
		if err := validateBundle(
			bundle,
			provider.CABundleSHA256,
			provider.CASHA256Fingerprints,
			now,
		); err != nil {
			return fmt.Errorf("provider %q CA bundle: %w", provider.Name, err)
		}
	}
	return nil
}
