package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/egress-proxy/internal/egresspolicy"
)

func TestGeneratedInstallationPassesEntrypointGate(t *testing.T) {
	now := time.Now().UTC()
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(root, "providers", "catalog.json")
	template := filepath.Join(root, "envoy.yaml.tmpl")
	plan, err := egresspolicy.Plan(catalog, root, template, []string{"anthropic"}, now)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if _, err := egresspolicy.Generate(
		catalog,
		root,
		template,
		output,
		[]string{"anthropic"},
		plan.EgressPolicySHA256,
		now,
	); err != nil {
		t.Fatal(err)
	}
	previousPaths := installPaths
	previousDigest := expectedPolicySHA256
	t.Cleanup(func() {
		installPaths = previousPaths
		expectedPolicySHA256 = previousDigest
	})
	etcEnvoy := filepath.Join(output, "etc", "envoy")
	installPaths = egresspolicy.InstallPaths{
		Policy:       filepath.Join(etcEnvoy, "provider-policy.json"),
		PolicyDigest: filepath.Join(etcEnvoy, "provider-policy.sha256"),
		Receipt:      filepath.Join(etcEnvoy, "provider-policy-receipt.json"),
		Config:       filepath.Join(etcEnvoy, "envoy.yaml"),
		CertDir:      filepath.Join(etcEnvoy, "certs"),
	}
	expectedPolicySHA256 = plan.EgressPolicySHA256
	t.Setenv("ENVOY_CONFIG", "")
	if err := run([]string{"validate"}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsEveryConfigOverride(t *testing.T) {
	for _, argument := range []string{
		"-c",
		"-c=/tmp/envoy.yaml",
		"-c/tmp/envoy.yaml",
		"--config-path",
		"--config-path=/tmp/envoy.yaml",
		"--config-yaml",
		"--config-yaml=static_resources:{}",
		"--config-any-future-flag",
	} {
		if err := rejectConfigOverrides([]string{argument}); err == nil {
			t.Fatalf("expected %s to fail", argument)
		}
	}
	for _, argument := range []string{"--log-level", "info", "--concurrency", "2"} {
		if err := rejectConfigOverrides([]string{argument}); err != nil {
			t.Fatalf("expected %s to remain allowed: %v", argument, err)
		}
	}
}

func TestRejectsEnvironmentConfigOverrideBeforeEveryCommand(t *testing.T) {
	t.Setenv("ENVOY_CONFIG", defaultConfig)
	for _, arguments := range [][]string{{"validate"}, {"receipt"}, {"health"}, {"--log-level", "info"}} {
		if err := run(arguments); err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("expected %v to reject ENVOY_CONFIG, got %v", arguments, err)
		}
	}
}

func TestInternalCommandsRejectExtraArguments(t *testing.T) {
	t.Setenv("ENVOY_CONFIG", "")
	for _, arguments := range [][]string{{"validate", "extra"}, {"receipt", "extra"}, {"health", "extra"}} {
		if err := run(arguments); err == nil {
			t.Fatalf("expected %v to fail", arguments)
		}
	}
}

func TestStartupFailuresUseOnlyStableSOCCategories(t *testing.T) {
	tests := map[string]string{
		"ENVOY_CONFIG overrides are forbidden":                         "config_override_rejected",
		"CA certificate is not valid yet":                              "ca_not_yet_valid",
		"CA certificate is expired":                                    "ca_expired",
		"CA certificate fingerprints do not match the reviewed order":  "ca_fingerprint_mismatch",
		"exact SANs must be nonempty":                                  "san_policy_invalid",
		"SNI must appear in the exact SAN list":                        "sni_policy_invalid",
		"CA bundle contains malformed PEM":                             "ca_material_invalid",
		"egress-policy digest file does not match the compiled digest": "policy_digest_mismatch",
		"unexpected internal failure":                                  "immutable_policy_validation_failed",
	}
	for message, expected := range tests {
		if actual := startupFailureReason(errors.New(message)); actual != expected {
			t.Fatalf("%q: expected %q, got %q", message, expected, actual)
		}
	}
}

func TestStartupSecurityEventUsesOnlyBoundedScalarFields(t *testing.T) {
	receipt := egresspolicy.Receipt{
		EgressPolicySHA256: "policy-digest",
		Providers: []egresspolicy.RuntimeProvider{
			{
				Name:                 "anthropic",
				SNI:                  "api.anthropic.com",
				ExactSANs:            []string{"api.anthropic.com"},
				CASHA256Fingerprints: []string{"first", "second"},
			},
			{
				Name:                 "future-reviewed-provider",
				SNI:                  "api.example.invalid",
				ExactSANs:            []string{"api.example.invalid", "alt.example.invalid"},
				CASHA256Fingerprints: []string{"third"},
			},
		},
	}
	event := startupSecurityEvent(receipt)
	expected := map[string]any{
		"schema_version":         1,
		"event":                  "aigw.egress.trust",
		"action":                 "startup_gate",
		"outcome":                "success",
		"policy_sha256":          "policy-digest",
		"providers":              "anthropic,future-reviewed-provider",
		"sni":                    "api.anthropic.com,api.example.invalid",
		"exact_sans":             "api.anthropic.com,api.example.invalid,alt.example.invalid",
		"ca_sha256_fingerprints": "first,second,third",
	}
	if len(event) != len(expected) {
		t.Fatalf("expected %d fields, got %d", len(expected), len(event))
	}
	for name, value := range expected {
		if event[name] != value {
			t.Fatalf("%s: expected %v, got %v", name, value, event[name])
		}
	}
}

func TestHealthRequiresLoopbackLiveResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("LIVE\n"))
	}))
	defer server.Close()
	if !strings.HasPrefix(server.URL, "http://127.0.0.1:") {
		t.Skip("httptest did not allocate a loopback IPv4 listener")
	}
	t.Setenv("ENVOY_ADMIN_READY_URL", server.URL)
	if err := health(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVOY_ADMIN_READY_URL", "https://example.com/ready")
	if err := health(); err == nil {
		t.Fatal("expected non-loopback health URL to fail")
	}
}
