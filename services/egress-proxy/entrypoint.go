// aigw-envoy-entrypoint validates the immutable egress policy before execing
// the shellless DHI Envoy runtime. It also provides the in-container probe and
// a non-secret release receipt.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"ai-gateway/egress-proxy/internal/egresspolicy"
)

const (
	defaultConfig        = "/etc/envoy/envoy.yaml"
	defaultPolicy        = "/etc/envoy/provider-policy.json"
	defaultPolicyDigest  = "/etc/envoy/provider-policy.sha256"
	defaultPolicyReceipt = "/etc/envoy/provider-policy-receipt.json"
	defaultCertDir       = "/etc/envoy/certs"
	defaultEnvoyBin      = "/usr/local/bin/envoy"
	defaultReadyURL      = "http://127.0.0.1:9901/ready"
	maxHealthBytes       = 64 << 10
)

// Docker sets this with -X after policygen independently regenerates and
// verifies the expected digest. A normal local go build intentionally fails
// closed if someone tries to use it as the image launcher.
var expectedPolicySHA256 = ""

var installPaths = egresspolicy.InstallPaths{
	Policy:       defaultPolicy,
	PolicyDigest: defaultPolicyDigest,
	Receipt:      defaultPolicyReceipt,
	Config:       defaultConfig,
	CertDir:      defaultCertDir,
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if isStartup(os.Args[1:]) {
			emitSecurityEvent(map[string]any{
				"schema_version": 1,
				"event":          "aigw.egress.trust",
				"action":         "startup_gate",
				"outcome":        "failed",
				"reason":         "immutable_policy_validation_failed",
			})
		}
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		fmt.Fprintln(os.Stderr, "Refusing to start (fail closed).")
		os.Exit(1)
	}
}

func run(args []string) error {
	if os.Getenv("ENVOY_CONFIG") != "" {
		return errors.New("ENVOY_CONFIG overrides are forbidden; the image policy is immutable")
	}
	if len(args) > 0 {
		switch args[0] {
		case "validate":
			if len(args) != 1 {
				return errors.New("validate accepts no arguments")
			}
			_, err := validateInstallation()
			return err
		case "receipt":
			if len(args) != 1 {
				return errors.New("receipt accepts no arguments")
			}
			receipt, err := validateInstallation()
			if err != nil {
				return err
			}
			content, err := egresspolicy.CanonicalReceiptBytes(receipt)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(content)
			return err
		case "health":
			if len(args) != 1 {
				return errors.New("health accepts no arguments")
			}
			return health()
		}
	}
	if err := rejectConfigOverrides(args); err != nil {
		return err
	}
	receipt, err := validateInstallation()
	if err != nil {
		return err
	}
	providers := make([]map[string]any, 0, len(receipt.Providers))
	for _, provider := range receipt.Providers {
		providers = append(providers, map[string]any{
			"name":                   provider.Name,
			"sni":                    provider.SNI,
			"exact_sans":             provider.ExactSANs,
			"ca_sha256_fingerprints": provider.CASHA256Fingerprints,
		})
	}
	emitSecurityEvent(map[string]any{
		"schema_version": 1,
		"event":          "aigw.egress.trust",
		"action":         "startup_gate",
		"outcome":        "success",
		"policy_sha256":  receipt.EgressPolicySHA256,
		"providers":      providers,
	})
	fmt.Fprintln(os.Stderr, "gate: immutable provider policy validated; starting envoy")
	envoyArgs := append([]string{"envoy", "-c", defaultConfig}, args...)
	return syscall.Exec(defaultEnvoyBin, envoyArgs, os.Environ())
}

func isStartup(args []string) bool {
	return len(args) == 0 || (args[0] != "validate" && args[0] != "receipt" && args[0] != "health")
}

func emitSecurityEvent(event map[string]any) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return
	}
	fmt.Fprintln(os.Stderr, "AIGW_SECURITY_EVENT "+string(encoded))
}

func rejectConfigOverrides(args []string) error {
	for _, argument := range args {
		shortConfig := strings.HasPrefix(argument, "-c") && !strings.HasPrefix(argument, "--")
		if shortConfig || strings.HasPrefix(argument, "--config-") {
			return fmt.Errorf("refusing config-override flag %q", argument)
		}
	}
	return nil
}

func validateInstallation() (egresspolicy.Receipt, error) {
	receipt, err := egresspolicy.ValidateInstallation(
		installPaths,
		expectedPolicySHA256,
		time.Now().UTC(),
	)
	if err != nil {
		return egresspolicy.Receipt{}, err
	}
	fmt.Fprintf(
		os.Stderr,
		"gate: policy %s providers=%s\n",
		receipt.EgressPolicySHA256,
		strings.Join(receipt.SelectedProviders, ","),
	)
	return receipt, nil
}

func health() error {
	readyURL := os.Getenv("ENVOY_ADMIN_READY_URL")
	if readyURL == "" {
		readyURL = defaultReadyURL
	}
	if !strings.HasPrefix(readyURL, "http://127.0.0.1:") &&
		!strings.HasPrefix(readyURL, "http://localhost:") {
		return errors.New("Envoy health URL must use loopback HTTP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, readyURL, nil)
	if err != nil {
		return err
	}
	client := http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not accepted")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("Envoy readiness request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthBytes+1))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || len(body) > maxHealthBytes ||
		!bytes.Contains(body, []byte("LIVE")) {
		return errors.New("Envoy admin endpoint is not LIVE")
	}
	return nil
}
