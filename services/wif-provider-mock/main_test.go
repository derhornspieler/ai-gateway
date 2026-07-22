package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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
