package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func encoded(value any) string {
	raw, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func signedToken(t *testing.T, key *rsa.PrivateKey, header, claims any) string {
	t.Helper()
	input := encoded(header) + "." + encoded(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func testConfig(t *testing.T, key *rsa.PrivateKey) config {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256", "n": n, "e": e,
	}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	return config{
		jwksFile: path,
		issuer:   "https://idp.wif.aigw.internal/realms/anthropic-wif",
		subject:  "service-account-anthropic-token-broker",
		audience: "https://api.anthropic.com",
	}
}

func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://idp.wif.aigw.internal/realms/anthropic-wif",
		"sub": "service-account-anthropic-token-broker",
		"aud": "https://api.anthropic.com",
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
}

func TestVerifyJWTChecksSignatureAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cfg := testConfig(t, key)
	token := signedToken(t, key, map[string]string{"alg": "RS256", "kid": "test-key"}, validClaims(now))
	if err := cfg.verifyJWT(token, now); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestVerifyJWTRejectsWrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	cfg := testConfig(t, key)
	claims := validClaims(now)
	claims["aud"] = []string{"https://api.anthropic.com", "account"}
	token := signedToken(t, key, map[string]string{"alg": "RS256", "kid": "test-key"}, claims)
	if err := cfg.verifyJWT(token, now); err == nil {
		t.Fatal("token with extra audience was accepted")
	}
}

func TestVerifyJWTRejectsExpiredToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	cfg := testConfig(t, key)
	claims := validClaims(now)
	claims["iat"] = now.Add(-20 * time.Minute).Unix()
	claims["exp"] = now.Add(-10 * time.Minute).Unix()
	token := signedToken(t, key, map[string]string{"alg": "RS256", "kid": "test-key"}, claims)
	if err := cfg.verifyJWT(token, now); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestProviderTokensAreRandomRotatedAndExpired(t *testing.T) {
	store := &tokenStore{}
	now := time.Now()
	first, err := store.issue(now)
	if err != nil {
		t.Fatal(err)
	}
	if !store.valid(first, now.Add(time.Minute)) {
		t.Fatal("fresh provider token was rejected")
	}

	second, err := store.issue(now.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two token exchanges returned the same token")
	}
	if store.valid(first, now.Add(3*time.Minute)) {
		t.Fatal("the previous provider token survived rotation")
	}
	if !store.valid(second, now.Add(3*time.Minute)) {
		t.Fatal("the current provider token was rejected")
	}
	if store.valid(second, now.Add(12*time.Minute)) {
		t.Fatal("an expired provider token was accepted")
	}
	if store.valid("", now) || store.valid("wrong", now) {
		t.Fatal("an invalid provider token was accepted")
	}
}

func TestRetryMarkerFailsOnlyTheFirstAttemptForEachModel(t *testing.T) {
	state := &messageTestState{retriedModels: make(map[string]bool)}
	if !state.firstAttempt("claude-preprod-a") {
		t.Fatal("first attempt was not selected for the planned retry")
	}
	if state.firstAttempt("claude-preprod-a") {
		t.Fatal("second attempt was selected for another planned retry")
	}
	if !state.firstAttempt("claude-preprod-b") {
		t.Fatal("a different model did not get its own planned retry")
	}
}

func TestProviderUsageKeepsMissingAndMalformedCasesDistinct(t *testing.T) {
	if providerUsage("AIGW_PREPROD_NO_USAGE_") != nil {
		t.Fatal("the missing-usage case emitted a usage object")
	}
	malformed := providerUsage("AIGW_PREPROD_INVALID_USAGE_")
	if malformed["input_tokens"] != "not-a-token-count" || malformed["output_tokens"] != 50 {
		t.Fatal("the malformed-usage case lost its exact invalid shape")
	}
	normal := providerUsage("normal request")
	if normal["input_tokens"] != 10 || normal["output_tokens"] != 50 {
		t.Fatal("the normal usage case changed")
	}
}

func TestMessageStreamHasBoundedAnthropicFramesAndFinalUsage(t *testing.T) {
	recorder := httptest.NewRecorder()
	usage := map[string]any{
		"input_tokens":  10,
		"output_tokens": 50,
	}

	writeMessageStream(recorder, "claude-preprod", usage)

	result := recorder.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		t.Fatalf("stream returned HTTP %d", result.StatusCode)
	}
	if result.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("stream did not use the event-stream content type")
	}
	body := recorder.Body.String()
	for _, marker := range []string{
		"event: message_start",
		`"text":"pong"`,
		`"input_tokens":10`,
		`"output_tokens":50`,
		"event: message_stop",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("stream omitted %q", marker)
		}
	}
}

func TestMessageStreamOmitsMissingUsageInsteadOfInventingZero(t *testing.T) {
	recorder := httptest.NewRecorder()

	writeMessageStream(recorder, "claude-preprod", nil)

	body := recorder.Body.String()
	if strings.Contains(body, `"input_tokens"`) {
		t.Fatal("the missing-usage stream invented input tokens")
	}
	if !strings.Contains(body, `"output_tokens":50`) {
		t.Fatal("the final provider usage delta was lost")
	}
}
