package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func encodedIndex(t *testing.T, analytics map[string]any) []byte {
	t.Helper()
	config := map[string]any{
		"modulePrefix": "vault",
		"environment":  "production",
		"rootURL":      "/ui/",
		"APP": map[string]any{
			"ANALYTICS_CONFIG": analytics,
		},
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.ReplaceAll(url.QueryEscape(string(payload)), "+", "%20")
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Vault</title>
<meta name="vault/config/environment" content="%s" />
<link rel="stylesheet" href="/ui/assets/vault-0123456789abcdef01234567.css">
</head><body><script src="/ui/assets/vault-0123456789abcdef01234567.js"></script></body></html>`, encoded))
}

func assetDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	files := map[string][]byte{
		"index.html":          encodedIndex(t, map[string]any{"enabled": false}),
		"metadata.json":       []byte(`{"version":"2.0.3"}`),
		"asset-manifest.json": []byte(`{"assets":[]}`),
		"robots.txt":          []byte("User-agent: *\nDisallow: /\n"),
		"sw.js":               []byte(`self.addEventListener("fetch",()=>{});`),
		"assets/vault-0123456789abcdef01234567.js":  []byte(`window.Vault={provider:"posthog-unused"};`),
		"assets/vault-0123456789abcdef01234567.css": []byte(`body{display:block}`),
	}
	for name, content := range files {
		filename := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func backendURL(t *testing.T, server *httptest.Server) *url.URL {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func newTestGateway(t *testing.T, server *httptest.Server) *gateway {
	t.Helper()
	assets := os.DirFS(assetDirectory(t))
	manifest, err := buildAssetManifest(assets)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newGateway(assets, manifest, backendURL(t, server))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.close)
	return handler
}

func TestUIRoutesAndSecurityHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/sys/health" {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(writer, `{"initialized":true,"sealed":true}`)
			return
		}
		http.NotFound(writer, request)
	}))
	defer backend.Close()
	handler := newTestGateway(t, backend)

	for _, test := range []struct {
		path        string
		status      int
		body        string
		cache       string
		contentType string
		workerScope string
	}{
		{path: "/ui/", status: http.StatusOK, body: "<title>Vault</title>", cache: "no-store", contentType: "text/html"},
		{path: "/ui/vault/secrets/kv", status: http.StatusOK, body: "<title>Vault</title>", cache: "no-store", contentType: "text/html"},
		{path: "/ui/assets/vault-0123456789abcdef01234567.js", status: http.StatusOK, body: "posthog-unused", cache: "public, max-age=31536000, immutable", contentType: "text/javascript"},
		{path: "/ui/sw.js", status: http.StatusOK, body: "fetch", cache: "no-store", contentType: "text/javascript", workerScope: serviceWorkerScope},
		{path: "/ui/assets/missing.js", status: http.StatusNotFound, body: "404 page not found", cache: "", contentType: "text/plain"},
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), test.body) {
				t.Fatalf("missing body contract %q", test.body)
			}
			if got := response.Header().Get("Cache-Control"); got != test.cache {
				t.Fatalf("Cache-Control=%q", got)
			}
			if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, test.contentType) {
				t.Fatalf("Content-Type=%q", got)
			}
			if got := response.Header().Get("Service-Worker-Allowed"); got != test.workerScope {
				t.Fatalf("Service-Worker-Allowed=%q", got)
			}
			if test.status == http.StatusOK {
				if got := response.Header().Get("Content-Security-Policy"); got != uiCSP {
					t.Fatalf("CSP=%q", got)
				}
				if strings.Contains(response.Header().Get("Content-Security-Policy"), "https:") {
					t.Fatal("CSP permits an external connection target")
				}
				if !strings.Contains(response.Header().Get("Content-Security-Policy"), "worker-src 'self'") {
					t.Fatal("CSP blocks the reviewed same-origin Vault service worker")
				}
			}
		})
	}
}

func TestProxyForwardsOnlyVaultAPIToFixedBackend(t *testing.T) {
	var mu sync.Mutex
	var requests int
	var receivedPath, receivedQuery, receivedHost string
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/sys/health" {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"initialized":true,"sealed":false}`)
			return
		}
		mu.Lock()
		requests++
		receivedPath = request.URL.Path
		receivedQuery = request.URL.RawQuery
		receivedHost = request.Host
		receivedHeaders = request.Header.Clone()
		mu.Unlock()
		writer.Header().Set("X-Vault-Test", "preserved")
		writer.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(writer, "vault-response")
	}))
	defer backend.Close()
	handler := newTestGateway(t, backend)

	request := httptest.NewRequest(http.MethodPost, "/v1/secret/data/project?upstream=http://attacker.invalid", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer preserved")
	request.Header.Set("X-Vault-Token", "vault-token")
	request.Header.Set("X-Vault-Namespace", "team/")
	request.Header.Set("Cookie", "_aigw_vault_oauth=must-not-reach-vault; other=also-strip")
	request.Header.Set("Forwarded", "host=attacker.invalid")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusTeapot || response.Body.String() != "vault-response" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Vault-Test") != "preserved" {
		t.Fatal("Vault response headers were not preserved")
	}
	if response.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("UI CSP must not alter Vault API responses")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 || receivedPath != "/v1/secret/data/project" ||
		receivedQuery != "upstream=http://attacker.invalid" || receivedHost != backendURL(t, backend).Host {
		t.Fatalf("unexpected backend request: count=%d path=%q query=%q host=%q", requests, receivedPath, receivedQuery, receivedHost)
	}
	for name, expected := range map[string]string{
		"Authorization":     "Bearer preserved",
		"X-Vault-Token":     "vault-token",
		"X-Vault-Namespace": "team/",
	} {
		if receivedHeaders.Get(name) != expected {
			t.Fatalf("%s was not preserved", name)
		}
	}
	if receivedHeaders.Get("Forwarded") != "" || receivedHeaders.Get("X-Forwarded-Host") != "" {
		t.Fatal("client forwarding metadata reached Vault")
	}
	if receivedHeaders.Get("Cookie") != "" {
		t.Fatal("OAuth or ambient browser cookies reached Vault")
	}

	for _, path := range []string{"/not-vault", "/ui/../v1/sys/health", "/v1/../sys/health"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound && response.Code != http.StatusBadRequest {
			t.Fatalf("%s unexpectedly returned %d", path, response.Code)
		}
	}
	if requests != 1 {
		t.Fatalf("non-Vault paths reached backend: %d", requests)
	}
}

func TestProxyUpstreamErrorLogIsConstantAndPathFree(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	handler := newTestGateway(t, backend)
	backend.Close()

	var captured bytes.Buffer
	original := log.Writer()
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(original) })

	request := httptest.NewRequest(
		http.MethodGet,
		"/v1/secret/data/customer-sensitive?token=query-secret",
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	logged := captured.String()
	if !strings.Contains(logged, "Vault upstream unavailable") ||
		strings.Contains(logged, "customer-sensitive") ||
		strings.Contains(logged, "query-secret") ||
		strings.Contains(logged, "/v1/") {
		t.Fatalf("upstream error log was not constant and path-free: %q", logged)
	}
}

func TestHealthAcceptsAuthenticSealedVaultAndRejectsArbitrary503(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   string
		status int
		want   int
	}{
		{name: "sealed", body: `{"initialized":true,"sealed":true}`, status: http.StatusServiceUnavailable, want: http.StatusOK},
		{name: "not-initialized", body: `{"initialized":false,"sealed":true}`, status: http.StatusNotImplemented, want: http.StatusOK},
		{name: "arbitrary-503", body: `temporarily unavailable`, status: http.StatusServiceUnavailable, want: http.StatusServiceUnavailable},
		{name: "wrong-status", body: `{"initialized":true,"sealed":false}`, status: http.StatusInternalServerError, want: http.StatusServiceUnavailable},
		{name: "false-sealed-503", body: `{"initialized":true,"sealed":false}`, status: http.StatusServiceUnavailable, want: http.StatusServiceUnavailable},
		{name: "false-ready-200", body: `{"initialized":true,"sealed":true}`, status: http.StatusOK, want: http.StatusServiceUnavailable},
		{name: "false-uninitialized-501", body: `{"initialized":true,"sealed":true}`, status: http.StatusNotImplemented, want: http.StatusServiceUnavailable},
		{name: "impossible-ready-uninitialized-501", body: `{"initialized":false,"sealed":false}`, status: http.StatusNotImplemented, want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer backend.Close()
			handler := newTestGateway(t, backend)
			request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestSanitizeIndexStructurallyDisablesAnalytics(t *testing.T) {
	original := encodedIndex(t, map[string]any{
		"enabled":    true,
		"provider":   "posthog",
		"project_id": "secret-project-id",
		"api_host":   "https://eu.i.posthog.com",
	})
	patched, err := sanitizeIndex(original)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(patched, []byte("secret-project-id")) || bytes.Contains(patched, []byte("eu.i.posthog.com")) {
		t.Fatal("analytics destination survived structural index patch")
	}
	if err := verifyRuntimeConfig(patched); err != nil {
		t.Fatal(err)
	}
	location, err := locateRuntimeConfig(patched)
	if err != nil {
		t.Fatal(err)
	}
	if location.config["modulePrefix"] != "vault" || location.config["rootURL"] != "/ui/" {
		t.Fatal("non-analytics runtime config was changed")
	}
}

func TestAssetVerificationRejectsStubTelemetryConfigAndSymlinks(t *testing.T) {
	directory := assetDirectory(t)
	if _, err := verifyAssetFS(os.DirFS(directory)); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("Vault UI is not available in this binary."), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAssetFS(os.DirFS(directory)); err == nil {
		t.Fatal("stub page passed asset verification")
	}

	directory = assetDirectory(t)
	if err := os.WriteFile(filepath.Join(directory, "index.html"), encodedIndex(t, map[string]any{"enabled": true}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAssetFS(os.DirFS(directory)); err == nil {
		t.Fatal("enabled analytics config passed asset verification")
	}

	directory = assetDirectory(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(directory, "assets", "escape.js")); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAssetFS(os.DirFS(directory)); err == nil {
		t.Fatal("symlinked asset passed verification")
	}
}

func TestProducerManifestRejectsMissingChangedAndExtraAssets(t *testing.T) {
	for _, mutation := range []struct {
		name string
		run  func(*testing.T, string)
	}{
		{
			name: "changed",
			run: func(t *testing.T, directory string) {
				filename := filepath.Join(directory, "assets/vault-0123456789abcdef01234567.js")
				if err := os.WriteFile(filename, []byte("changed"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing",
			run: func(t *testing.T, directory string) {
				if err := os.Remove(filepath.Join(directory, "robots.txt")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra",
			run: func(t *testing.T, directory string) {
				if err := os.WriteFile(filepath.Join(directory, "unexpected.txt"), []byte("extra"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			directory := assetDirectory(t)
			assets := os.DirFS(directory)
			manifest, err := buildAssetManifest(assets)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyAssetManifest(assets, manifest); err != nil {
				t.Fatal(err)
			}
			mutation.run(t, directory)
			if _, err := verifyAssetManifest(assets, manifest); err == nil {
				t.Fatal("asset mutation passed producer-manifest verification")
			}
		})
	}
}
