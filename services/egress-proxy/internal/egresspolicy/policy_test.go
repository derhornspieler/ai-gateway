package egresspolicy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

func TestCommittedCatalogAndCanonicalSelection(t *testing.T) {
	root, catalogPath, _ := componentFiles(t)
	catalog, err := LoadCatalog(catalogPath, root, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Providers) != 1 {
		t.Fatalf("got %d catalog providers", len(catalog.Providers))
	}
	selected, err := SelectProviders(catalog, []string{"anthropic", "anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{selected[0].Name}; !equalStrings(got, []string{"anthropic"}) {
		t.Fatalf("unexpected canonical selection: %v", got)
	}
	for _, requested := range [][]string{nil, {}, {"unknown"}, {"openai"}, {"api.openai.com"}, {"../certs/openai-ca.pem"}, {" openai"}} {
		if _, err := SelectProviders(catalog, requested); err == nil {
			t.Fatalf("expected selection %q to fail", requested)
		}
	}
}

func TestCatalogRejectsDuplicateKeysUnknownFieldsAndChangedProvenance(t *testing.T) {
	root, catalogPath, _ := componentFiles(t)
	original, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"duplicate key":     bytes.Replace(original, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "schema_version": 1,`), 1),
		"unknown field":     bytes.Replace(original, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "hostname_override": "evil.example",`), 1),
		"provenance digest": bytes.Replace(original, []byte(`a72ea049dcecae19751134891dfbe9adc1b06f66ce42cbe4a662abb7a4e9dd02`), []byte(strings.Repeat("0", 64)), 1),
	}
	for name, content := range mutations {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "catalog.json")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCatalog(path, root, testNow); err == nil {
				t.Fatal("expected changed catalog to fail")
			}
		})
	}
}

func TestPlanIsDeterministicAndUnapprovedProviderFails(t *testing.T) {
	root, catalogPath, templatePath := componentFiles(t)
	first, err := Plan(catalogPath, root, templatePath, []string{"anthropic", "anthropic"}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(catalogPath, root, templatePath, []string{"anthropic"}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("equivalent selections produced different receipts")
	}
	if _, err := Plan(catalogPath, root, templatePath, []string{"openai"}, testNow); err == nil {
		t.Fatal("unapproved OpenAI provider did not fail closed")
	}
}

func TestGenerateContainsOnlySelectedProviderAndValidates(t *testing.T) {
	paths, receipt := generateInstall(t, []string{"anthropic"})
	entries, err := os.ReadDir(paths.CertDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "anthropic-ca.pem" {
		t.Fatalf("unexpected selected CA files: %v", entries)
	}
	config, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte("api.anthropic.com")) || bytes.Contains(config, []byte("api.openai.com")) {
		t.Fatal("generated config did not contain only the selected provider")
	}
	validated, err := ValidateInstallation(paths, receipt.EgressPolicySHA256, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(validated, receipt) {
		t.Fatal("validated receipt differs from generated receipt")
	}
}

func TestCheckedInReferenceConfigMatchesCanonicalDefault(t *testing.T) {
	paths, _ := generateInstall(t, []string{"anthropic"})
	generated, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	root, _, _ := componentFiles(t)
	reference, err := os.ReadFile(filepath.Join(root, "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reference, generated) {
		t.Fatal("envoy.yaml is stale; regenerate the checked-in reference config")
	}
}

func TestGenerateRejectsWrongDigestAndNonemptyOutput(t *testing.T) {
	root, catalogPath, templatePath := componentFiles(t)
	output := t.TempDir()
	if _, err := Generate(catalogPath, root, templatePath, output, []string{"anthropic"}, strings.Repeat("0", 64), testNow); err == nil {
		t.Fatal("expected wrong policy digest to fail")
	}
	if err := os.WriteFile(filepath.Join(output, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(catalogPath, root, templatePath, []string{"anthropic"}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(catalogPath, root, templatePath, output, []string{"anthropic"}, plan.EgressPolicySHA256, testNow); err == nil {
		t.Fatal("expected nonempty output to fail")
	}
}

func TestNormalizeTimestampsUsesSourceDateEpoch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeChanged(t, path, []byte("content"))
	if err := NormalizeTimestamps(root, 0); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, root} {
		info, err := os.Stat(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if info.ModTime().Unix() != 0 {
			t.Fatalf("%s timestamp is %s", candidate, info.ModTime())
		}
	}
}

func TestInstallationRejectsEveryChangedImmutableInput(t *testing.T) {
	mutations := map[string]func(*testing.T, InstallPaths){
		"digest file": func(t *testing.T, paths InstallPaths) {
			writeChanged(t, paths.PolicyDigest, []byte(strings.Repeat("0", 64)+"\n"))
		},
		"policy": func(t *testing.T, paths InstallPaths) {
			content, _ := os.ReadFile(paths.Policy)
			writeChanged(t, paths.Policy, append(content, ' '))
		},
		"receipt": func(t *testing.T, paths InstallPaths) {
			content, _ := os.ReadFile(paths.Receipt)
			writeChanged(t, paths.Receipt, append(content, ' '))
		},
		"route": func(t *testing.T, paths InstallPaths) {
			replaceFile(t, paths.Config, "/anthropic/", "/changed/")
		},
		"endpoint hostname": func(t *testing.T, paths InstallPaths) {
			replaceFile(t, paths.Config, "api.anthropic.com", "evil.example.com")
		},
		"SNI": func(t *testing.T, paths InstallPaths) {
			replaceFile(t, paths.Config, "sni: api.anthropic.com", "sni: evil.example.com")
		},
		"exact SAN": func(t *testing.T, paths InstallPaths) {
			replaceFile(t, paths.Config, "matcher: { exact: api.anthropic.com }", "matcher: { exact: evil.example.com }")
		},
		"CA path": func(t *testing.T, paths InstallPaths) {
			replaceFile(t, paths.Config, "anthropic-ca.pem", "other-ca.pem")
		},
		"CA bytes": func(t *testing.T, paths InstallPaths) {
			writeChanged(t, filepath.Join(paths.CertDir, "anthropic-ca.pem"), []byte("not a certificate\n"))
		},
		"unexpected CA": func(t *testing.T, paths InstallPaths) {
			writeChanged(t, filepath.Join(paths.CertDir, "extra.pem"), []byte("extra\n"))
		},
		"missing CA": func(t *testing.T, paths InstallPaths) {
			if err := os.Remove(filepath.Join(paths.CertDir, "anthropic-ca.pem")); err != nil {
				t.Fatal(err)
			}
		},
		"symlink CA": func(t *testing.T, paths InstallPaths) {
			ca := filepath.Join(paths.CertDir, "anthropic-ca.pem")
			content, _ := os.ReadFile(ca)
			target := filepath.Join(filepath.Dir(paths.CertDir), "outside.pem")
			writeChanged(t, target, content)
			if err := os.Remove(ca); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, ca); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			paths, receipt := generateInstall(t, []string{"anthropic"})
			mutate(t, paths)
			if _, err := ValidateInstallation(paths, receipt.EgressPolicySHA256, testNow); err == nil {
				t.Fatal("expected changed installation to fail")
			}
		})
	}
}

func TestRuntimePolicyShapeRejectsUnsafeFields(t *testing.T) {
	paths, _ := generateInstall(t, []string{"anthropic"})
	content, err := os.ReadFile(paths.Policy)
	if err != nil {
		t.Fatal(err)
	}
	var baseline RuntimePolicy
	if err := decodeStrictJSON(content, &baseline); err != nil {
		t.Fatal(err)
	}
	example := baseline.Providers[0]
	example.Name = "example"
	example.APIHostname = "api.example.com"
	example.RoutePrefix = "/example/"
	example.SNI = "api.example.com"
	example.ExactSANs = []string{"api.example.com"}
	example.CAFile = "example-ca.pem"
	baseline.SelectedProviders = []string{"anthropic", "example"}
	baseline.Providers = append(baseline.Providers, example)
	content, err = CanonicalPolicyBytes(baseline)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*RuntimePolicy){
		"schema":          func(policy *RuntimePolicy) { policy.SchemaVersion = 2 },
		"empty selection": func(policy *RuntimePolicy) { policy.SelectedProviders = nil; policy.Providers = nil },
		"order": func(policy *RuntimePolicy) {
			policy.SelectedProviders[0], policy.SelectedProviders[1] = policy.SelectedProviders[1], policy.SelectedProviders[0]
		},
		"hostname":     func(policy *RuntimePolicy) { policy.Providers[0].APIHostname = "https://api.anthropic.com" },
		"route":        func(policy *RuntimePolicy) { policy.Providers[0].RoutePrefix = "anthropic" },
		"overlap":      func(policy *RuntimePolicy) { policy.Providers[1].RoutePrefix = "/anthropic/child/" },
		"SNI":          func(policy *RuntimePolicy) { policy.Providers[0].SNI = "other.example.com" },
		"wildcard SAN": func(policy *RuntimePolicy) { policy.Providers[0].ExactSANs = []string{"*.anthropic.com"} },
		"CA traversal": func(policy *RuntimePolicy) { policy.Providers[0].CAFile = "../ca.pem" },
		"hash case": func(policy *RuntimePolicy) {
			policy.Providers[0].CABundleSHA256 = strings.ToUpper(policy.Providers[0].CABundleSHA256)
		},
		"duplicate fingerprint": func(policy *RuntimePolicy) {
			policy.Providers[0].CASHA256Fingerprints[1] = policy.Providers[0].CASHA256Fingerprints[0]
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var policy RuntimePolicy
			if err := decodeStrictJSON(content, &policy); err != nil {
				t.Fatal(err)
			}
			mutate(&policy)
			if err := validateRuntimePolicyShape(policy); err == nil {
				t.Fatal("expected unsafe runtime policy to fail")
			}
		})
	}
}

func TestStrictJSONRejectsDuplicateKeysAtEveryDepth(t *testing.T) {
	for _, content := range []string{
		`{"schema_version":1,"schema_version":1}`,
		`{"outer":{"name":"a","name":"b"}}`,
		`[{"name":"a","name":"b"}]`,
	} {
		var destination any
		if err := decodeStrictJSON([]byte(content), &destination); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("expected duplicate key rejection for %s, got %v", content, err)
		}
	}
}

func TestBundleValidationFailureModes(t *testing.T) {
	valid, validHash, validFingerprint := makeTestCertificate(t, testNow.Add(-time.Hour), testNow.Add(time.Hour), true, true)
	second, _, secondFingerprint := makeTestCertificate(t, testNow.Add(-time.Hour), testNow.Add(time.Hour), true, true)
	expired, expiredHash, expiredFingerprint := makeTestCertificate(t, testNow.Add(-2*time.Hour), testNow, true, true)
	future, futureHash, futureFingerprint := makeTestCertificate(t, testNow.Add(time.Second), testNow.Add(time.Hour), true, true)
	leaf, leafHash, leafFingerprint := makeTestCertificate(t, testNow.Add(-time.Hour), testNow.Add(time.Hour), false, false)
	noCertSign, noCertSignHash, noCertSignFingerprint := makeTestCertificate(t, testNow.Add(-time.Hour), testNow.Add(time.Hour), true, false)
	cases := map[string]struct {
		content      []byte
		bundleHash   string
		fingerprints []string
	}{
		"wrong bundle hash": {valid, strings.Repeat("0", 64), []string{validFingerprint}},
		"wrong fingerprint": {valid, validHash, []string{strings.Repeat("0", 64)}},
		"expired":           {expired, expiredHash, []string{expiredFingerprint}},
		"not yet valid":     {future, futureHash, []string{futureFingerprint}},
		"leaf":              {leaf, leafHash, []string{leafFingerprint}},
		"no cert sign":      {noCertSign, noCertSignHash, []string{noCertSignFingerprint}},
		"leading text":      {append([]byte("bad\n"), valid...), sha256Hex(append([]byte("bad\n"), valid...)), []string{validFingerprint}},
		"trailing text":     {append(append([]byte(nil), valid...), []byte("bad\n")...), sha256Hex(append(append([]byte(nil), valid...), []byte("bad\n")...)), []string{validFingerprint}},
		"non-certificate":   {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}), "", []string{validFingerprint}},
		"invalid DER":       {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}), "", []string{validFingerprint}},
		"duplicate":         {append(append([]byte(nil), valid...), valid...), "", []string{validFingerprint, validFingerprint}},
		"wrong order":       {append(append([]byte(nil), valid...), second...), "", []string{secondFingerprint, validFingerprint}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if test.bundleHash == "" {
				test.bundleHash = sha256Hex(test.content)
			}
			if err := validateBundle(test.content, test.bundleHash, test.fingerprints, testNow); err == nil {
				t.Fatal("expected bundle validation to fail")
			}
		})
	}
}

func componentFiles(t *testing.T) (string, string, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, "providers", "catalog.json"), filepath.Join(root, "envoy.yaml.tmpl")
}

func generateInstall(t *testing.T, providers []string) (InstallPaths, Receipt) {
	t.Helper()
	root, catalogPath, templatePath := componentFiles(t)
	plan, err := Plan(catalogPath, root, templatePath, providers, testNow)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	receipt, err := Generate(catalogPath, root, templatePath, output, providers, plan.EgressPolicySHA256, testNow)
	if err != nil {
		t.Fatal(err)
	}
	etcEnvoy := filepath.Join(output, "etc", "envoy")
	return InstallPaths{
		Policy:       filepath.Join(etcEnvoy, "provider-policy.json"),
		PolicyDigest: filepath.Join(etcEnvoy, "provider-policy.sha256"),
		Receipt:      filepath.Join(etcEnvoy, "provider-policy-receipt.json"),
		Config:       filepath.Join(etcEnvoy, "envoy.yaml"),
		CertDir:      filepath.Join(etcEnvoy, "certs"),
	}, receipt
}

func writeChanged(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceFile(t *testing.T, path, old, replacement string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(content, []byte(old), []byte(replacement), 1)
	if bytes.Equal(content, changed) {
		t.Fatalf("fixture does not contain %q", old)
	}
	writeChanged(t, path, changed)
}

func makeTestCertificate(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
	isCA bool,
	canSign bool,
) ([]byte, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.KeyUsageDigitalSignature
	if canSign {
		usage |= x509.KeyUsageCertSign
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "test certificate"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	digest := sha256.Sum256(der)
	return content, sha256Hex(content), hex.EncodeToString(digest[:])
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatal(err)
	}
	return serial
}
