package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	listenAddress     = "0.0.0.0:8080"
	assetRoot         = "/opt/vault-ui"
	assetManifestPath = "/opt/vault-ui.sha256.json"
	// The upstream is deliberately a compile-time constant. Neither a request
	// parameter nor an environment variable can turn this process into an open
	// proxy or select a second Vault backend.
	vaultUpstream             = "http://vault:8200"
	expectedRuntimeExecutable = "/usr/local/bin/vault-ui-proxy"
	serviceWorkerScope        = "/v1/sys/storage/raft/snapshot"

	maxAssetBytes    = 32 << 20
	maxHealthBytes   = 64 << 10
	maxManifestBytes = 1 << 20

	missingUIMessage = "vault ui is not available in this binary"
	uiCSP            = "default-src 'none'; connect-src 'self'; img-src 'self' data:; " +
		"script-src 'self'; worker-src 'self'; style-src 'unsafe-inline' 'self'; form-action 'none'; " +
		"frame-ancestors 'none'; font-src 'self'"
)

var (
	errInvalidAssets = errors.New("invalid Vault UI assets")
	forbiddenAssets  = [][]byte{
		[]byte(missingUIMessage),
	}
	metaTagPattern              = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	metaAttrPattern             = regexp.MustCompile(`(?is)([a-z][a-z0-9_:/.-]*)\s*=\s*("[^"]*"|'[^']*')`)
	acceptedVaultHealthStatuses = map[int]struct{}{
		http.StatusOK:                 {},
		http.StatusTooManyRequests:    {},
		472:                           {}, // disaster-recovery mode replication secondary
		473:                           {}, // performance standby
		http.StatusNotImplemented:     {}, // not initialized
		http.StatusServiceUnavailable: {}, // sealed
	}
)

type gateway struct {
	assets         fs.FS
	index          []byte
	proxy          *httputil.ReverseProxy
	healthClient   *http.Client
	vaultHealthURL string
	transport      *http.Transport
}

type assetRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type assetManifest struct {
	Schema int           `json:"schema"`
	Files  []assetRecord `json:"files"`
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "verify-assets":
			if len(os.Args) != 4 {
				log.Fatal("usage: vault-ui-proxy verify-assets ASSET_DIRECTORY MANIFEST")
			}
			manifest, err := os.ReadFile(os.Args[3])
			if err != nil || len(manifest) > maxManifestBytes {
				log.Fatal("Vault UI manifest read failed")
			}
			if _, err := verifyAssetManifest(os.DirFS(os.Args[2]), manifest); err != nil {
				log.Fatal("Vault UI asset verification failed")
			}
			return
		case "write-manifest":
			if len(os.Args) != 4 {
				log.Fatal("usage: vault-ui-proxy write-manifest ASSET_DIRECTORY MANIFEST")
			}
			if err := writeAssetManifestFile(os.DirFS(os.Args[2]), os.Args[3]); err != nil {
				log.Fatal("Vault UI manifest generation failed")
			}
			return
		case "sanitize-index":
			if len(os.Args) != 3 {
				log.Fatal("usage: vault-ui-proxy sanitize-index INDEX_HTML")
			}
			if err := sanitizeIndexFile(os.Args[2]); err != nil {
				log.Fatal("Vault UI index privacy patch failed")
			}
			return
		case "check":
			if len(os.Args) != 2 {
				log.Fatal("usage: vault-ui-proxy check")
			}
			if err := checkLocalServer(); err != nil {
				log.Fatal("Vault UI proxy health contract failed")
			}
			return
		default:
			log.Fatal("unsupported command")
		}
	}

	if err := verifyDirectRuntimeProcess(); err != nil {
		log.Fatal("Vault UI proxy process contract failed")
	}
	backend, err := url.Parse(vaultUpstream)
	if err != nil {
		log.Fatal("invalid compiled Vault upstream")
	}
	manifest, err := os.ReadFile(assetManifestPath)
	if err != nil || len(manifest) > maxManifestBytes {
		log.Fatal("Vault UI manifest read failed")
	}
	handler, err := newGateway(os.DirFS(assetRoot), manifest, backend)
	if err != nil {
		log.Fatal("Vault UI proxy initialization failed")
	}
	defer handler.close()

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(os.Stderr, "vault-ui-proxy: ", 0),
	}
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("Vault UI proxy stopped")
	}
}

func newGateway(assets fs.FS, manifest []byte, backend *url.URL) (*gateway, error) {
	if backend == nil || backend.Scheme != "http" || backend.Host == "" ||
		backend.User != nil || backend.Path != "" || backend.RawPath != "" ||
		backend.RawQuery != "" || backend.Fragment != "" {
		return nil, errors.New("unsafe Vault upstream")
	}
	index, err := verifyAssetManifest(assets, manifest)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(backend)
			request.Out.Host = backend.Host
			// The OAuth session cookie authorizes only the outer UI gate; Vault
			// neither consumes nor needs it. Strip every Cookie value at this final
			// hop while retaining the caller's explicit Vault API credentials
			// (Authorization, X-Vault-Token, and X-Vault-Namespace). Removing
			// client-supplied forwarding metadata keeps the OAuth boundary
			// authoritative as well.
			request.Out.Header.Del("Cookie")
			request.Out.Header.Del("Forwarded")
			for name := range request.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
					request.Out.Header.Del(name)
				}
			}
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			// Do not turn a Vault mount, secret path, or query-bearing request into
			// log metadata when the fixed backend is unavailable.
			log.Print("Vault upstream unavailable")
			http.Error(writer, "Bad Gateway", http.StatusBadGateway)
		},
	}

	healthClient := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &gateway{
		assets:         assets,
		index:          index,
		proxy:          proxy,
		healthClient:   healthClient,
		vaultHealthURL: backend.String() + "/v1/sys/health?standbyok=true&perfstandbyok=true",
		transport:      transport,
	}, nil
}

func (g *gateway) close() {
	g.transport.CloseIdleConnections()
}

func (g *gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.URL.Path == "/healthz":
		g.serveHealth(writer, request)
	case request.URL.Path == "/":
		if !allowReadMethod(writer, request) {
			return
		}
		setUIHeaders(writer.Header())
		http.Redirect(writer, request, "/ui/", http.StatusPermanentRedirect)
	case request.URL.Path == "/ui":
		if !allowReadMethod(writer, request) {
			return
		}
		setUIHeaders(writer.Header())
		http.Redirect(writer, request, "/ui/", http.StatusPermanentRedirect)
	case strings.HasPrefix(request.URL.Path, "/ui/"):
		g.serveUI(writer, request)
	case request.URL.Path == "/v1" || strings.HasPrefix(request.URL.Path, "/v1/"):
		if !safePath(request.URL.Path, "/v1") {
			http.Error(writer, "Bad Request", http.StatusBadRequest)
			return
		}
		g.proxy.ServeHTTP(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (g *gateway) serveUI(writer http.ResponseWriter, request *http.Request) {
	if !allowReadMethod(writer, request) {
		return
	}
	relative := strings.TrimPrefix(request.URL.Path, "/ui/")
	if relative == "" {
		g.serveIndex(writer, request)
		return
	}
	if !safePath(relative, "") || !fs.ValidPath(relative) {
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}

	file, err := g.assets.Open(relative)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && path.Ext(relative) == "" {
			g.serveIndex(writer, request)
			return
		}
		http.NotFound(writer, request)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxAssetBytes {
		http.NotFound(writer, request)
		return
	}

	setUIHeaders(writer.Header())
	if relative == "sw.js" {
		// The upstream Vault UI registers this worker solely to attach a Vault
		// token to Raft snapshot downloads. Do not permit it to claim /ui, /
		// or generic /v1 requests on the authenticated origin.
		writer.Header().Set("Service-Worker-Allowed", serviceWorkerScope)
	}
	if fingerprinted(relative) {
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		writer.Header().Set("Cache-Control", "no-store")
	}
	if contentType := mime.TypeByExtension(path.Ext(relative)); contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	if seeker, ok := file.(io.ReadSeeker); ok {
		http.ServeContent(writer, request, path.Base(relative), info.ModTime(), seeker)
		return
	}
	content, err := readBounded(file, info.Size(), maxAssetBytes)
	if err != nil {
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(writer, request, path.Base(relative), info.ModTime(), bytes.NewReader(content))
}

func (g *gateway) serveIndex(writer http.ResponseWriter, request *http.Request) {
	setUIHeaders(writer.Header())
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(writer, request, "index.html", time.Time{}, bytes.NewReader(g.index))
}

func (g *gateway) serveHealth(writer http.ResponseWriter, request *http.Request) {
	if !allowReadMethod(writer, request) {
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := g.checkVault(request.Context()); err != nil {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = io.WriteString(writer, "ok\n")
	}
}

func (g *gateway) checkVault(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, g.vaultHealthURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "aigw-vault-ui-proxy-health")
	response, err := g.healthClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if _, ok := acceptedVaultHealthStatuses[response.StatusCode]; !ok {
		return fmt.Errorf("unexpected Vault health status: %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthBytes+1))
	if err != nil || len(body) > maxHealthBytes {
		return errors.New("invalid Vault health response")
	}
	var health struct {
		Initialized *bool `json:"initialized"`
		Sealed      *bool `json:"sealed"`
	}
	if err := json.Unmarshal(body, &health); err != nil || health.Initialized == nil || health.Sealed == nil {
		return errors.New("invalid Vault health payload")
	}
	switch response.StatusCode {
	case http.StatusNotImplemented:
		if *health.Initialized || !*health.Sealed {
			return errors.New("inconsistent uninitialized Vault health payload")
		}
	case http.StatusServiceUnavailable:
		if !*health.Initialized || !*health.Sealed {
			return errors.New("inconsistent sealed Vault health payload")
		}
	default:
		if !*health.Initialized || *health.Sealed {
			return errors.New("inconsistent ready Vault health payload")
		}
	}
	return nil
}

func allowReadMethod(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		return true
	}
	writer.Header().Set("Allow", "GET, HEAD")
	http.Error(writer, "Method Not Allowed", http.StatusMethodNotAllowed)
	return false
}

func safePath(value, requiredPrefix string) bool {
	if requiredPrefix != "" && value != requiredPrefix && !strings.HasPrefix(value, requiredPrefix+"/") {
		return false
	}
	if strings.ContainsAny(value, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func setUIHeaders(header http.Header) {
	header.Set("Content-Security-Policy", uiCSP)
	header.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

// verifyDirectRuntimeProcess makes the direct-entrypoint assumption
// executable policy. It runs before the HTTP listener exists, so Docker has
// not started the healthcheck yet: the proxy must itself be PID 1 and the only
// process in the container. This prevents the dormant Vault executable in the
// DHI runtime base (and any supervisor) from running alongside the proxy.
func verifyDirectRuntimeProcess() error {
	if os.Getpid() != 1 {
		return errors.New("proxy is not PID 1")
	}
	executable, err := os.Readlink("/proc/1/exe")
	if err != nil || executable != expectedRuntimeExecutable {
		return errors.New("PID 1 is not the reviewed proxy executable")
	}
	cmdline, err := os.ReadFile("/proc/1/cmdline")
	if err != nil || len(cmdline) == 0 || len(cmdline) > 4096 ||
		string(bytes.SplitN(cmdline, []byte{0}, 2)[0]) != expectedRuntimeExecutable {
		return errors.New("PID 1 command line is not the reviewed proxy executable")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return errors.New("cannot inventory runtime processes")
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr == nil && pid != 1 {
			return errors.New("unexpected additional runtime process")
		}
	}
	return nil
}

func fingerprinted(name string) bool {
	base := path.Base(name)
	for _, field := range strings.FieldsFunc(base, func(r rune) bool { return r == '-' || r == '.' }) {
		if len(field) < 20 {
			continue
		}
		if strings.Trim(field, "0123456789abcdef") == "" {
			return true
		}
	}
	return false
}

func verifyAssetFS(assets fs.FS) ([]byte, error) {
	for _, required := range []string{
		"index.html", "metadata.json", "asset-manifest.json", "robots.txt", "sw.js",
	} {
		info, err := fs.Stat(assets, required)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errInvalidAssets
		}
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil || len(index) == 0 || len(index) > maxAssetBytes {
		return nil, errInvalidAssets
	}
	lowerIndex := bytes.ToLower(index)
	if !bytes.Contains(lowerIndex, []byte("<!doctype html")) ||
		!bytes.Contains(lowerIndex, []byte("<title>vault</title>")) ||
		!bytes.Contains(index, []byte("/ui/")) {
		return nil, errInvalidAssets
	}
	if err := verifyRuntimeConfig(index); err != nil {
		return nil, errInvalidAssets
	}

	var hasJavaScript, hasStylesheet, hasMetadata bool
	err = fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errInvalidAssets
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxAssetBytes {
			return errInvalidAssets
		}
		file, err := assets.Open(name)
		if err != nil {
			return err
		}
		content, readErr := readBounded(file, info.Size(), maxAssetBytes)
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		lower := bytes.ToLower(content)
		for _, forbidden := range forbiddenAssets {
			if bytes.Contains(lower, forbidden) {
				return errInvalidAssets
			}
		}
		switch strings.ToLower(path.Ext(name)) {
		case ".js":
			hasJavaScript = true
		case ".css":
			hasStylesheet = true
		}
		if name == "metadata.json" {
			hasMetadata = true
		}
		return nil
	})
	if err != nil || !hasJavaScript || !hasStylesheet || !hasMetadata {
		return nil, errInvalidAssets
	}
	return index, nil
}

func buildAssetManifest(assets fs.FS) ([]byte, error) {
	if _, err := verifyAssetFS(assets); err != nil {
		return nil, err
	}
	manifest := assetManifest{Schema: 1}
	err := fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errInvalidAssets
		}
		if entry.IsDir() {
			return nil
		}
		if !fs.ValidPath(name) || name == "." {
			return errInvalidAssets
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxAssetBytes {
			return errInvalidAssets
		}
		file, err := assets.Open(name)
		if err != nil {
			return err
		}
		digest := sha256.New()
		copied, copyErr := io.Copy(digest, io.LimitReader(file, maxAssetBytes+1))
		finalInfo, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil || copied != info.Size() ||
			finalInfo.Size() != info.Size() || copied > maxAssetBytes {
			return errInvalidAssets
		}
		manifest.Files = append(manifest.Files, assetRecord{
			Path:   name,
			SHA256: fmt.Sprintf("%x", digest.Sum(nil)),
			Size:   copied,
		})
		return nil
	})
	if err != nil || len(manifest.Files) == 0 {
		return nil, errInvalidAssets
	}
	sort.Slice(manifest.Files, func(left, right int) bool {
		return manifest.Files[left].Path < manifest.Files[right].Path
	})
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded)+1 > maxManifestBytes {
		return nil, errInvalidAssets
	}
	return append(encoded, '\n'), nil
}

func parseAssetManifest(encoded []byte) (*assetManifest, error) {
	if len(encoded) == 0 || len(encoded) > maxManifestBytes {
		return nil, errInvalidAssets
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest assetManifest
	if err := decoder.Decode(&manifest); err != nil || manifest.Schema != 1 || len(manifest.Files) == 0 {
		return nil, errInvalidAssets
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errInvalidAssets
	}
	previous := ""
	for _, record := range manifest.Files {
		if !fs.ValidPath(record.Path) || record.Path == "." || record.Path <= previous ||
			record.Size < 0 || record.Size > maxAssetBytes || len(record.SHA256) != sha256.Size*2 ||
			strings.Trim(record.SHA256, "0123456789abcdef") != "" {
			return nil, errInvalidAssets
		}
		previous = record.Path
	}
	return &manifest, nil
}

func verifyAssetManifest(assets fs.FS, encoded []byte) ([]byte, error) {
	expected, err := parseAssetManifest(encoded)
	if err != nil {
		return nil, err
	}
	actualEncoded, err := buildAssetManifest(assets)
	if err != nil {
		return nil, err
	}
	actual, err := parseAssetManifest(actualEncoded)
	if err != nil || len(actual.Files) != len(expected.Files) {
		return nil, errInvalidAssets
	}
	for index := range expected.Files {
		if expected.Files[index] != actual.Files[index] {
			return nil, errInvalidAssets
		}
	}
	return fs.ReadFile(assets, "index.html")
}

func writeAssetManifestFile(assets fs.FS, filename string) error {
	manifest, err := buildAssetManifest(assets)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(path.Dir(filename), ".vault-ui-manifest.*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(manifest); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	committed = true
	return nil
}

type runtimeConfigLocation struct {
	valueStart int
	valueEnd   int
	config     map[string]any
}

func locateRuntimeConfig(index []byte) (*runtimeConfigLocation, error) {
	var found *runtimeConfigLocation
	for _, tagLocation := range metaTagPattern.FindAllIndex(index, -1) {
		tag := index[tagLocation[0]:tagLocation[1]]
		attributes := metaAttrPattern.FindAllSubmatchIndex(tag, -1)
		var name string
		var contentStart, contentEnd = -1, -1
		for _, location := range attributes {
			key := strings.ToLower(string(tag[location[2]:location[3]]))
			quoted := tag[location[4]:location[5]]
			if len(quoted) < 2 {
				return nil, errInvalidAssets
			}
			value := html.UnescapeString(string(quoted[1 : len(quoted)-1]))
			switch key {
			case "name":
				name = value
			case "content":
				contentStart = tagLocation[0] + location[4] + 1
				contentEnd = tagLocation[0] + location[5] - 1
			}
		}
		if name != "vault/config/environment" {
			continue
		}
		if contentStart < 0 || contentEnd < contentStart {
			return nil, errInvalidAssets
		}
		decoded, err := url.QueryUnescape(string(index[contentStart:contentEnd]))
		if err != nil {
			return nil, errInvalidAssets
		}
		var config map[string]any
		if err := json.Unmarshal([]byte(decoded), &config); err != nil {
			return nil, errInvalidAssets
		}
		if found != nil {
			return nil, errInvalidAssets
		}
		found = &runtimeConfigLocation{
			valueStart: contentStart,
			valueEnd:   contentEnd,
			config:     config,
		}
	}
	if found == nil {
		return nil, errInvalidAssets
	}
	return found, nil
}

func verifyRuntimeConfig(index []byte) error {
	location, err := locateRuntimeConfig(index)
	if err != nil {
		return err
	}
	app, ok := location.config["APP"].(map[string]any)
	if !ok {
		return errInvalidAssets
	}
	analytics, ok := app["ANALYTICS_CONFIG"].(map[string]any)
	if !ok || len(analytics) != 1 {
		return errInvalidAssets
	}
	enabled, ok := analytics["enabled"].(bool)
	if !ok || enabled {
		return errInvalidAssets
	}
	return nil
}

func sanitizeIndex(index []byte) ([]byte, error) {
	location, err := locateRuntimeConfig(index)
	if err != nil {
		return nil, err
	}
	app, ok := location.config["APP"].(map[string]any)
	if !ok {
		return nil, errInvalidAssets
	}
	app["ANALYTICS_CONFIG"] = map[string]any{"enabled": false}
	encodedConfig, err := json.Marshal(location.config)
	if err != nil {
		return nil, errInvalidAssets
	}
	encoded := strings.ReplaceAll(url.QueryEscape(string(encodedConfig)), "+", "%20")
	patched := make([]byte, 0, len(index)-location.valueEnd+location.valueStart+len(encoded))
	patched = append(patched, index[:location.valueStart]...)
	patched = append(patched, encoded...)
	patched = append(patched, index[location.valueEnd:]...)
	if err := verifyRuntimeConfig(patched); err != nil {
		return nil, err
	}
	if bytes.Contains(bytes.ToLower(patched), []byte("eu.i.posthog.com")) {
		return nil, errInvalidAssets
	}
	return patched, nil
}

func sanitizeIndexFile(filename string) error {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() > maxAssetBytes {
		return errInvalidAssets
	}
	original, err := os.ReadFile(filename)
	if err != nil || int64(len(original)) != info.Size() {
		return errInvalidAssets
	}
	patched, err := sanitizeIndex(original)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(path.Dir(filename), ".index.html.*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := temporary.Write(patched); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	committed = true
	return nil
}

func readBounded(reader io.Reader, announced, maximum int64) ([]byte, error) {
	if announced < 0 || announced > maximum {
		return nil, errInvalidAssets
	}
	content, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(content)) > maximum || int64(len(content)) != announced {
		return nil, errInvalidAssets
	}
	return content, nil
}

func checkLocalServer() error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, endpoint := range []string{
		"http://127.0.0.1:8080/healthz",
		"http://127.0.0.1:8080/ui/",
		"http://127.0.0.1:8080/ui/sw.js",
	} {
		response, err := client.Get(endpoint)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxAssetBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(body) > maxAssetBytes {
			return errors.New("local contract failed")
		}
		if strings.HasSuffix(endpoint, "/ui/") {
			lower := bytes.ToLower(body)
			if !bytes.Contains(lower, []byte("<title>vault</title>")) ||
				bytes.Contains(lower, []byte(missingUIMessage)) ||
				verifyRuntimeConfig(body) != nil ||
				response.Header.Get("Content-Security-Policy") != uiCSP ||
				response.Header.Get("Service-Worker-Allowed") != "" ||
				strings.Contains(response.Header.Get("Content-Security-Policy"), "https:") {
				return errors.New("local UI contract failed")
			}
		}
		if strings.HasSuffix(endpoint, "/ui/sw.js") &&
			(response.Header.Get("Content-Security-Policy") != uiCSP ||
				response.Header.Get("Service-Worker-Allowed") != serviceWorkerScope ||
				!bytes.Contains(body, []byte(serviceWorkerScope))) {
			return errors.New("local service-worker contract failed")
		}
	}
	return nil
}
