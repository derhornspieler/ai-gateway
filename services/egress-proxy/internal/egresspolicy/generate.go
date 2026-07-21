package egresspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// NormalizeTimestamps makes generated layer metadata reproducible. It rejects
// symlinks because build output must contain ordinary files and directories.
func NormalizeTimestamps(root string, sourceDateEpoch int64) error {
	if sourceDateEpoch < 0 {
		return errors.New("source-date epoch cannot be negative")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("timestamp root must be a real directory")
	}
	var paths []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("generated tree contains symlink %q", path)
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	fixed := time.Unix(sourceDateEpoch, 0).UTC()
	for index := len(paths) - 1; index >= 0; index-- {
		if err := os.Chtimes(paths[index], fixed, fixed); err != nil {
			return fmt.Errorf("normalize timestamp for %q: %w", paths[index], err)
		}
	}
	return nil
}

func Generate(
	catalogPath string,
	componentRoot string,
	templatePath string,
	outputRoot string,
	requested []string,
	expectedPolicySHA256 string,
	now time.Time,
) (Receipt, error) {
	catalog, err := LoadCatalog(catalogPath, componentRoot, now)
	if err != nil {
		return Receipt{}, err
	}
	selected, err := SelectProviders(catalog, requested)
	if err != nil {
		return Receipt{}, err
	}
	if err := requireEmptyDirectory(outputRoot); err != nil {
		return Receipt{}, err
	}

	providers := make([]RuntimeProvider, 0, len(selected))
	selectedNames := make([]string, 0, len(selected))
	for _, provider := range selected {
		selectedNames = append(selectedNames, provider.Name)
		providers = append(providers, RuntimeProvider{
			Name:                 provider.Name,
			APIHostname:          provider.APIHostname,
			RoutePrefix:          provider.RoutePrefix,
			SNI:                  provider.SNI,
			ExactSANs:            append([]string(nil), provider.ExactSANs...),
			CAFile:               provider.Name + "-ca.pem",
			CABundleSHA256:       provider.CABundleSHA256,
			CASHA256Fingerprints: append([]string(nil), provider.CASHA256Fingerprints...),
			ProvenanceSHA256:     provider.ProvenanceSHA256,
		})
	}

	templateBytes, err := readRegularBounded(templatePath, maxConfigBytes)
	if err != nil {
		return Receipt{}, fmt.Errorf("read Envoy template: %w", err)
	}
	parsedTemplate, err := template.New("envoy.yaml").Option("missingkey=error").Parse(string(templateBytes))
	if err != nil {
		return Receipt{}, fmt.Errorf("parse Envoy template: %w", err)
	}
	var config bytes.Buffer
	if err := parsedTemplate.Execute(&config, struct {
		Providers []RuntimeProvider
	}{Providers: providers}); err != nil {
		return Receipt{}, fmt.Errorf("render Envoy template: %w", err)
	}
	// YAML files end with one newline and no empty lines. This keeps lint and
	// policy digests stable even if the human-readable template has spacing.
	trimmedConfig := bytes.TrimRight(config.Bytes(), "\n")
	config.Reset()
	_, _ = config.Write(trimmedConfig)
	_ = config.WriteByte('\n')
	if config.Len() == 0 || config.Len() > maxConfigBytes {
		return Receipt{}, errors.New("generated Envoy config has an invalid size")
	}

	policy := RuntimePolicy{
		SchemaVersion:     PolicySchemaVersion,
		SelectedProviders: selectedNames,
		Providers:         providers,
		EnvoyConfigSHA256: sha256Hex(config.Bytes()),
	}
	policyBytes, err := CanonicalPolicyBytes(policy)
	if err != nil {
		return Receipt{}, err
	}
	policyDigest := sha256Hex(policyBytes)
	if expectedPolicySHA256 != "" {
		if !validSHA256(expectedPolicySHA256) {
			return Receipt{}, errors.New("expected egress-policy SHA-256 is not canonical")
		}
		if policyDigest != expectedPolicySHA256 {
			return Receipt{}, fmt.Errorf(
				"generated egress-policy SHA-256 %s does not match expected %s",
				policyDigest,
				expectedPolicySHA256,
			)
		}
	}
	receipt := Receipt{
		SchemaVersion:      PolicySchemaVersion,
		EgressPolicySHA256: policyDigest,
		EnvoyConfigSHA256:  policy.EnvoyConfigSHA256,
		SelectedProviders:  append([]string(nil), selectedNames...),
		Providers:          append([]RuntimeProvider(nil), providers...),
	}
	receiptBytes, err := CanonicalReceiptBytes(receipt)
	if err != nil {
		return Receipt{}, err
	}

	etcEnvoy := filepath.Join(outputRoot, "etc", "envoy")
	certDir := filepath.Join(etcEnvoy, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return Receipt{}, fmt.Errorf("create generated image directories: %w", err)
	}
	writes := []struct {
		path    string
		content []byte
	}{
		{filepath.Join(etcEnvoy, "envoy.yaml"), config.Bytes()},
		{filepath.Join(etcEnvoy, "provider-policy.json"), policyBytes},
		{filepath.Join(etcEnvoy, "provider-policy.sha256"), []byte(policyDigest + "\n")},
		{filepath.Join(etcEnvoy, "provider-policy-receipt.json"), receiptBytes},
	}
	for _, write := range writes {
		if err := os.WriteFile(write.path, write.content, 0o644); err != nil {
			return Receipt{}, fmt.Errorf("write generated file %q: %w", write.path, err)
		}
	}
	for _, provider := range selected {
		path := filepath.Join(certDir, provider.Name+"-ca.pem")
		if err := os.WriteFile(path, provider.bundleBytes, 0o644); err != nil {
			return Receipt{}, fmt.Errorf("write selected CA bundle %q: %w", path, err)
		}
	}
	return receipt, nil
}

// Plan returns the same canonical receipt as Generate without retaining build
// output. Release scripts call this command instead of parsing catalog JSON.
func Plan(
	catalogPath string,
	componentRoot string,
	templatePath string,
	requested []string,
	now time.Time,
) (Receipt, error) {
	outputRoot, err := os.MkdirTemp("", "aigw-egress-policy-")
	if err != nil {
		return Receipt{}, err
	}
	defer os.RemoveAll(outputRoot)
	return Generate(catalogPath, componentRoot, templatePath, outputRoot, requested, "", now)
}

func CanonicalReceiptBytes(receipt Receipt) ([]byte, error) {
	content, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func CanonicalPolicyBytes(policy RuntimePolicy) ([]byte, error) {
	if err := validateRuntimePolicyShape(policy); err != nil {
		return nil, err
	}
	content, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func requireEmptyDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0o755)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("generation output must be a real directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("generation output directory must be empty")
	}
	return nil
}

func validateRuntimePolicyShape(policy RuntimePolicy) error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("runtime policy schema must be %d", PolicySchemaVersion)
	}
	if !isSortedUnique(policy.SelectedProviders) {
		return errors.New("selected providers must be nonempty, sorted, and unique")
	}
	if len(policy.Providers) != len(policy.SelectedProviders) {
		return errors.New("selected provider names and provider records differ")
	}
	if !validSHA256(policy.EnvoyConfigSHA256) {
		return errors.New("Envoy config SHA-256 must be 64 lowercase hexadecimal characters")
	}
	hostnames := make(map[string]struct{}, len(policy.Providers))
	routes := make(map[string]struct{}, len(policy.Providers))
	caFiles := make(map[string]struct{}, len(policy.Providers))
	for index, provider := range policy.Providers {
		if provider.Name != policy.SelectedProviders[index] || !validProviderName(provider.Name) {
			return errors.New("runtime provider records must follow canonical selected-provider order")
		}
		if !validHostname(provider.APIHostname) || !validRoutePrefix(provider.RoutePrefix) ||
			!validHostname(provider.SNI) {
			return fmt.Errorf("provider %q has an invalid hostname, route, or SNI", provider.Name)
		}
		if !isSortedUnique(provider.ExactSANs) {
			return fmt.Errorf("provider %q exact SANs must be nonempty, sorted, and unique", provider.Name)
		}
		sniFound := false
		for _, san := range provider.ExactSANs {
			if !validHostname(san) {
				return fmt.Errorf("provider %q has invalid exact SAN %q", provider.Name, san)
			}
			if san == provider.SNI {
				sniFound = true
			}
		}
		if !sniFound {
			return fmt.Errorf("provider %q SNI is absent from its exact SANs", provider.Name)
		}
		if provider.CAFile != provider.Name+"-ca.pem" || filepath.Base(provider.CAFile) != provider.CAFile {
			return fmt.Errorf("provider %q has a noncanonical CA filename", provider.Name)
		}
		if !validSHA256(provider.CABundleSHA256) || !validSHA256(provider.ProvenanceSHA256) {
			return fmt.Errorf("provider %q has an invalid bundle or provenance SHA-256", provider.Name)
		}
		if len(provider.CASHA256Fingerprints) == 0 {
			return fmt.Errorf("provider %q has no CA certificate fingerprints", provider.Name)
		}
		fingerprints := make(map[string]struct{}, len(provider.CASHA256Fingerprints))
		for _, fingerprint := range provider.CASHA256Fingerprints {
			if !validSHA256(fingerprint) {
				return fmt.Errorf("provider %q has invalid CA fingerprint %q", provider.Name, fingerprint)
			}
			if _, found := fingerprints[fingerprint]; found {
				return fmt.Errorf("provider %q has a duplicate CA fingerprint", provider.Name)
			}
			fingerprints[fingerprint] = struct{}{}
		}
		if _, found := hostnames[provider.APIHostname]; found {
			return fmt.Errorf("duplicate runtime hostname %q", provider.APIHostname)
		}
		if _, found := routes[provider.RoutePrefix]; found {
			return fmt.Errorf("duplicate runtime route %q", provider.RoutePrefix)
		}
		if _, found := caFiles[provider.CAFile]; found {
			return fmt.Errorf("duplicate runtime CA file %q", provider.CAFile)
		}
		hostnames[provider.APIHostname] = struct{}{}
		routes[provider.RoutePrefix] = struct{}{}
		caFiles[provider.CAFile] = struct{}{}
	}
	for left := range policy.Providers {
		for right := left + 1; right < len(policy.Providers); right++ {
			leftRoute := policy.Providers[left].RoutePrefix
			rightRoute := policy.Providers[right].RoutePrefix
			if strings.HasPrefix(leftRoute, rightRoute) || strings.HasPrefix(rightRoute, leftRoute) {
				return fmt.Errorf("runtime routes %q and %q overlap", leftRoute, rightRoute)
			}
		}
	}
	return nil
}
