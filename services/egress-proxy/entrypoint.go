// aigw-envoy-entrypoint validates the egress trust policy before execing the
// shellless DHI Envoy runtime. It also provides the in-container ready probe.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	defaultConfig   = "/etc/envoy/envoy.yaml"
	defaultEnvoyBin = "/usr/local/bin/envoy"
	defaultReadyURL = "http://127.0.0.1:9901/ready"
	maxConfigBytes  = 4 << 20
	maxBundleBytes  = 2 << 20
	maxHealthBytes  = 64 << 10
)

var (
	trustedCA     = regexp.MustCompile(`trusted_ca:\s*\{\s*filename:\s*([^,}\s]+)`)
	systemBundles = map[string]struct{}{
		"/etc/ssl/certs/ca-certificates.crt": {},
		"/etc/ssl/cert.pem":                  {},
		"/etc/pki/tls/certs/ca-bundle.crt":   {},
		"/etc/ssl/certs/ca-bundle.crt":       {},
	}
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		fmt.Fprintln(os.Stderr, "Refusing to start (fail closed).")
		os.Exit(1)
	}
}

func run(args []string) error {
	config := os.Getenv("ENVOY_CONFIG")
	if config == "" {
		config = defaultConfig
	}
	if len(args) > 0 {
		switch args[0] {
		case "validate":
			if len(args) != 1 {
				return errors.New("validate accepts no arguments")
			}
			return validateConfig(config)
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
	if err := validateConfig(config); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "gate: pinning enforcement present; starting envoy")
	envoyArgs := append([]string{"envoy", "-c", config}, args...)
	return syscall.Exec(defaultEnvoyBin, envoyArgs, os.Environ())
}

func rejectConfigOverrides(args []string) error {
	for _, argument := range args {
		if argument == "-c" || argument == "--config-path" || argument == "--config-yaml" ||
			strings.HasPrefix(argument, "--config-path=") || strings.HasPrefix(argument, "--config-yaml=") {
			return fmt.Errorf("refusing config-override flag %q", argument)
		}
	}
	return nil
}

func validateConfig(configPath string) error {
	if !filepath.IsAbs(configPath) {
		return errors.New("ENVOY_CONFIG must be an absolute path")
	}
	configuration, err := readBounded(configPath, maxConfigBytes)
	if err != nil {
		return fmt.Errorf("read Envoy config: %w", err)
	}
	active := uncomment(configuration)
	if bytes.Contains(active, []byte("REPLACE_WITH_SPKI")) {
		return errors.New("Envoy config contains an active REPLACE_WITH_SPKI placeholder")
	}
	tlsContexts := bytes.Count(active, []byte("UpstreamTlsContext"))
	if tlsContexts < 1 {
		return errors.New("Envoy config contains no upstream TLS context")
	}
	matches := trustedCA.FindAllSubmatch(active, -1)
	if len(matches) != tlsContexts {
		return fmt.Errorf("found %d upstream TLS contexts but %d trusted_ca files", tlsContexts, len(matches))
	}
	for _, match := range matches {
		path := strings.Trim(string(match[1]), `"'`)
		if err := validateBundle(path); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "gate: trusted_ca OK ->", path)
	}
	return nil
}

func uncomment(configuration []byte) []byte {
	lines := bytes.Split(configuration, []byte("\n"))
	for index, line := range lines {
		if comment := bytes.IndexByte(line, '#'); comment >= 0 {
			lines[index] = line[:comment]
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

func validateBundle(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("trusted_ca path %q is not absolute", path)
	}
	if _, forbidden := systemBundles[filepath.Clean(path)]; forbidden {
		return fmt.Errorf("trusted_ca %q is a system/public root bundle", path)
	}
	bundle, err := readBounded(path, maxBundleBytes)
	if err != nil {
		return fmt.Errorf("read trusted_ca %q: %w", path, err)
	}
	if bytes.Contains(bundle, []byte("REPLACE_WITH_")) {
		return fmt.Errorf("trusted_ca %q contains a placeholder", path)
	}
	rest := bundle
	validCAs := 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("trusted_ca %q contains an invalid certificate", path)
		}
		if certificate.IsCA {
			validCAs++
		}
	}
	if validCAs == 0 {
		return fmt.Errorf("trusted_ca %q contains no valid CA certificate", path)
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	if len(content) == 0 {
		return nil, errors.New("file is empty")
	}
	return content, nil
}

func health() error {
	readyURL := os.Getenv("ENVOY_ADMIN_READY_URL")
	if readyURL == "" {
		readyURL = defaultReadyURL
	}
	if !strings.HasPrefix(readyURL, "http://127.0.0.1:") && !strings.HasPrefix(readyURL, "http://localhost:") {
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
	if response.StatusCode != http.StatusOK || len(body) > maxHealthBytes || !bytes.Contains(body, []byte("LIVE")) {
		return errors.New("Envoy admin endpoint is not LIVE")
	}
	return nil
}
