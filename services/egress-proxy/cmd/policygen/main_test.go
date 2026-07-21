package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ai-gateway/egress-proxy/internal/egresspolicy"
)

func TestCLIRejectsArbitraryTrustInputsAndEmptySelection(t *testing.T) {
	for _, arguments := range [][]string{
		{"plan"},
		{"plan", "--hostname", "evil.example"},
		{"plan", "--ca-file", "/tmp/evil.pem"},
		{"plan", "--provider", "anthropic", "--providers-csv", "anthropic"},
		{"unknown", "--provider", "anthropic"},
	} {
		if err := run(arguments); err == nil {
			t.Fatalf("expected %v to fail", arguments)
		}
	}
}

func TestPlanCanonicalizesRepeatedProvidersAndRejectsNoncanonicalCSV(t *testing.T) {
	withComponentWorkingDirectory(t)
	if err := run([]string{"plan", "--provider", "anthropic", "--provider", "anthropic"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"plan", "--providers-csv", "anthropic,anthropic"}); err == nil {
		t.Fatal("expected noncanonical CSV to fail")
	}
	if err := run([]string{"plan", "--provider", "unknown"}); err == nil {
		t.Fatal("expected unknown provider to fail")
	}
	if err := run([]string{"plan", "--provider", "openai"}); err == nil {
		t.Fatal("expected unapproved OpenAI provider to fail")
	}
}

func TestGenerateRequiresAndChecksPlannedDigest(t *testing.T) {
	root := withComponentWorkingDirectory(t)
	receipt, err := egresspolicy.Plan(
		filepath.Join(root, catalogPath),
		root,
		filepath.Join(root, templatePath),
		[]string{"anthropic"},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if err := run([]string{
		"generate",
		"--providers-csv", "anthropic",
		"--output", output,
		"--expect-policy-sha256", receipt.EgressPolicySHA256,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "etc", "envoy", "provider-policy-receipt.json")); err != nil {
		t.Fatal(err)
	}
}

func withComponentWorkingDirectory(t *testing.T) string {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(old, "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	return root
}
