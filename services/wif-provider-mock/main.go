// wif-provider-mock is the preprod stand-in for Anthropic.
// It accepts a token only after it verifies the real Keycloak signature and claims.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxBodyBytes = 1 << 20
	testTokenTTL = 10 * time.Minute
)

type tokenStore struct {
	mutex   sync.Mutex
	digest  [sha256.Size]byte
	expires time.Time
	ready   bool
}

type messageTestState struct {
	mutex         sync.Mutex
	retriedModels map[string]bool
}

type config struct {
	address          string
	certFile         string
	keyFile          string
	caFile           string
	serverName       string
	jwksFile         string
	issuer           string
	subject          string
	audience         string
	organizationID   string
	serviceAccountID string
	federationRuleID string
	workspaceID      string
	tokens           *tokenStore
	messageTests     *messageTestState
}

type jwksDocument struct {
	Keys []json.RawMessage `json:"keys"`
}

type rsaJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Expires  json.Number     `json:"exp"`
	IssuedAt json.Number     `json:"iat"`
}

type exchangeRequest struct {
	GrantType      string `json:"grant_type"`
	Assertion      string `json:"assertion"`
	FederationRule string `json:"federation_rule_id"`
	Organization   string `json:"organization_id"`
	ServiceAccount string `json:"service_account_id"`
	Workspace      string `json:"workspace_id"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "serve":
		if err := serve(cfg); err != nil {
			log.Fatal(err)
		}
	case "health":
		if err := health(cfg); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown command %q", command)
	}
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func loadConfig() (config, error) {
	var cfg config
	var err error
	fields := []struct {
		name   string
		target *string
	}{
		{"TLS_CERT_FILE", &cfg.certFile},
		{"TLS_KEY_FILE", &cfg.keyFile},
		{"TLS_CA_FILE", &cfg.caFile},
		{"TLS_SERVER_NAME", &cfg.serverName},
		{"KEYCLOAK_JWKS_FILE", &cfg.jwksFile},
		{"EXPECTED_ISSUER", &cfg.issuer},
		{"EXPECTED_SUBJECT", &cfg.subject},
		{"EXPECTED_AUDIENCE", &cfg.audience},
		{"EXPECTED_ORGANIZATION_ID", &cfg.organizationID},
		{"EXPECTED_SERVICE_ACCOUNT_ID", &cfg.serviceAccountID},
		{"EXPECTED_FEDERATION_RULE_ID", &cfg.federationRuleID},
		{"EXPECTED_WORKSPACE_ID", &cfg.workspaceID},
	}
	for _, field := range fields {
		*field.target, err = required(field.name)
		if err != nil {
			return config{}, err
		}
	}
	cfg.address = strings.TrimSpace(os.Getenv("LISTEN_ADDRESS"))
	if cfg.address == "" {
		cfg.address = "0.0.0.0:8443"
	}
	if cfg.serverName != "wif-provider-mock.aigw.internal" && !strings.HasSuffix(cfg.serverName, ".aigw.internal") {
		return config{}, errors.New("TLS_SERVER_NAME must be under aigw.internal")
	}
	cfg.tokens = &tokenStore{}
	cfg.messageTests = &messageTestState{retriedModels: make(map[string]bool)}
	return cfg, nil
}

func serve(cfg config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("POST /v1/oauth/token", cfg.exchange)
	mux.HandleFunc("POST /v1/messages", cfg.messages)
	server := &http.Server{
		Addr:              cfg.address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	log.Printf("preprod WIF mock listening on %s", cfg.address)
	return server.ListenAndServeTLS(cfg.certFile, cfg.keyFile)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		http.Error(w, "application/json is required", http.StatusUnsupportedMediaType)
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxBodyBytes {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (cfg config) exchange(w http.ResponseWriter, r *http.Request) {
	var request exchangeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.GrantType != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
		request.FederationRule != cfg.federationRuleID ||
		request.Organization != cfg.organizationID ||
		request.ServiceAccount != cfg.serviceAccountID ||
		request.Workspace != cfg.workspaceID {
		http.Error(w, "invalid enrollment identifiers", http.StatusBadRequest)
		return
	}
	if err := cfg.verifyJWT(request.Assertion, time.Now()); err != nil {
		http.Error(w, "invalid assertion", http.StatusUnauthorized)
		return
	}
	token, err := cfg.tokens.issue(time.Now())
	if err != nil {
		http.Error(w, "could not issue token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(testTokenTTL / time.Second),
	})
}

func (cfg config) messages(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimSpace(r.Header.Get("x-api-key"))
	if credential == "" {
		credential = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if !cfg.tokens.valid(credential, time.Now()) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request map[string]json.RawMessage
	if !decodeJSON(w, r, &request) {
		return
	}
	var model string
	var messages []json.RawMessage
	if json.Unmarshal(request["model"], &model) != nil || model == "" ||
		json.Unmarshal(request["messages"], &messages) != nil || len(messages) == 0 {
		http.Error(w, "model and messages are required", http.StatusBadRequest)
		return
	}
	messageDocument := string(request["messages"])
	if strings.Contains(messageDocument, "AIGW_PREPROD_FAIL_ALWAYS_") {
		http.Error(w, "planned preprod provider failure", http.StatusInternalServerError)
		return
	}
	if strings.Contains(messageDocument, "AIGW_PREPROD_RETRY_ONCE_") &&
		cfg.messageTests.firstAttempt(model) {
		http.Error(w, "planned preprod retry", http.StatusInternalServerError)
		return
	}

	usage := providerUsage(messageDocument)

	var stream bool
	_ = json.Unmarshal(request["stream"], &stream)
	if stream {
		writeMessageStream(w, model, usage)
		return
	}
	response := map[string]any{
		"id":            "msg_preprod_001",
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       []map[string]string{{"type": "text", "text": "pong"}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
	}
	if usage != nil {
		response["usage"] = usage
	}
	writeJSON(w, http.StatusOK, response)
}

func providerUsage(messageDocument string) map[string]any {
	usage := map[string]any{
		"input_tokens":                10,
		"cache_creation_input_tokens": 50,
		"cache_read_input_tokens":     40,
		"output_tokens":               50,
		"cache_creation": map[string]int{
			"ephemeral_5m_input_tokens": 20,
			"ephemeral_1h_input_tokens": 30,
		},
	}
	if strings.Contains(messageDocument, "AIGW_PREPROD_NO_USAGE_") {
		return nil
	}
	if strings.Contains(messageDocument, "AIGW_PREPROD_INVALID_USAGE_") {
		usage["input_tokens"] = "not-a-token-count"
	}
	return usage
}

func (state *messageTestState) firstAttempt(model string) bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.retriedModels[model] {
		return false
	}
	state.retriedModels[model] = true
	return true
}

func writeMessageStream(w http.ResponseWriter, model string, usage map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	frames := []map[string]any{
		{
			"type": "message_start",
			"message": map[string]any{
				"id": "msg_preprod_stream_001", "type": "message",
				"role": "assistant", "model": model, "content": []any{},
				"stop_reason": nil, "stop_sequence": nil,
			},
		},
		{"type": "content_block_start", "index": 0, "content_block": map[string]string{"type": "text", "text": ""}},
		{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": "pong"}},
		{"type": "content_block_stop", "index": 0},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 50}},
		{"type": "message_stop"},
	}
	if usage != nil {
		frames[0]["message"].(map[string]any)["usage"] = usage
	}
	for _, frame := range frames {
		encoded, err := json.Marshal(frame)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", frame["type"], encoded)
	}
}

func (store *tokenStore) issue(now time.Time) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", errors.New("secure random token generation failed")
	}
	token := "sk-ant-oat01-" + base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	store.mutex.Lock()
	store.digest = digest
	store.expires = now.Add(testTokenTTL)
	store.ready = true
	store.mutex.Unlock()
	return token, nil
}

func (store *tokenStore) valid(token string, now time.Time) bool {
	if token == "" {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.ready && now.Before(store.expires) &&
		subtle.ConstantTimeCompare(digest[:], store.digest[:]) == 1
}

func decodeSegment(value string, target any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}

func (cfg config) verifyJWT(token string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("JWT must have three segments")
	}
	var header jwtHeader
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "RS256" || header.Kid == "" {
		return errors.New("JWT header is invalid")
	}
	var claims jwtClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return errors.New("JWT claims are invalid")
	}
	if claims.Issuer != cfg.issuer || claims.Subject != cfg.subject {
		return errors.New("JWT identity claims do not match")
	}
	if err := exactAudience(claims.Audience, cfg.audience); err != nil {
		return err
	}
	expires, err := claims.Expires.Int64()
	if err != nil || expires <= now.Unix() || expires > now.Add(15*time.Minute).Unix() {
		return errors.New("JWT expiry is invalid")
	}
	issued, err := claims.IssuedAt.Int64()
	if err != nil || issued > now.Add(30*time.Second).Unix() || issued < now.Add(-15*time.Minute).Unix() || expires <= issued {
		return errors.New("JWT issued-at time is invalid")
	}
	key, err := loadRSAKey(cfg.jwksFile, header.Kid)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("JWT signature is invalid")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return errors.New("JWT signature verification failed")
	}
	return nil
}

func exactAudience(raw json.RawMessage, expected string) error {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		if single == expected {
			return nil
		}
		return errors.New("JWT audience does not match")
	}
	var values []string
	if json.Unmarshal(raw, &values) == nil && len(values) == 1 && values[0] == expected {
		return nil
	}
	return errors.New("JWT audience does not match exactly")
}

func loadRSAKey(path, kid string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maxBodyBytes {
		return nil, errors.New("JWKS file is unavailable")
	}
	var document jwksDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, errors.New("JWKS file is invalid")
	}
	for _, encoded := range document.Keys {
		var key rsaJWK
		if json.Unmarshal(encoded, &key) != nil || key.Kid != kid {
			continue
		}
		if key.Kty != "RSA" || key.Alg != "RS256" || (key.Use != "" && key.Use != "sig") {
			return nil, errors.New("JWKS key is not an RS256 signing key")
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil || len(n) < 256 {
			return nil, errors.New("JWKS modulus is invalid")
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("JWKS exponent is invalid")
		}
		exponent := 0
		for _, octet := range e {
			exponent = exponent<<8 | int(octet)
		}
		if exponent < 3 || exponent%2 == 0 {
			return nil, errors.New("JWKS exponent is invalid")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
	}
	return nil, errors.New("JWKS signing key was not found")
}

func health(cfg config) error {
	caPEM, err := os.ReadFile(cfg.caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("test CA is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: cfg.serverName,
	}}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:8443/healthz", nil)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("health endpoint is not ready")
	}
	return nil
}
