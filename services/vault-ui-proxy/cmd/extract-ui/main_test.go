package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCompilerHashMatchesGoEmbedSmallFileAlgorithm(t *testing.T) {
	got := compilerHash(nil)
	if hex.EncodeToString(got[:]) != "1cb0c44298fc1c149afbf4c8996fb924" {
		t.Fatalf("unexpected empty-file compiler hash: %x", got)
	}
}

func TestSafeDestinationRejectsEscapesAndPlatformAmbiguity(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, "assets", "app.js")
	if got, err := safeDestination(root, "assets/app.js"); err != nil || got != want {
		t.Fatalf("safe path: got=%q err=%v", got, err)
	}
	for _, candidate := range []string{
		"../secret", "/absolute", "assets/../../secret", `assets\app.js`, ".", "assets//app.js",
	} {
		if _, err := safeDestination(root, candidate); err == nil {
			t.Fatalf("unsafe path %q was accepted", candidate)
		}
	}
}

func TestOpenImageRejectsNonExecutableInput(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "not-an-executable")
	if err := os.WriteFile(filename, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if image, err := openImage(filename); err == nil {
		_ = image.close()
		t.Fatal("non-executable input was accepted")
	}
}

func TestByteHelpers(t *testing.T) {
	if !allZero([]byte{0, 0, 0}) || allZero([]byte{0, 1, 0}) {
		t.Fatal("allZero returned an incorrect result")
	}
	if !equalBytes([]byte{1, 2}, []byte{1, 2}) ||
		equalBytes([]byte{1, 2}, []byte{1, 3}) ||
		equalBytes([]byte{1}, []byte{1, 2}) {
		t.Fatal("equalBytes returned an incorrect result")
	}
}
