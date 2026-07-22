package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range entries {
		if strings.HasSuffix(name, "/") {
			header := &zip.FileHeader{Name: name}
			header.SetMode(os.ModeDir | 0o755)
			if _, err := writer.CreateHeader(header); err != nil {
				t.Fatal(err)
			}
			continue
		}
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plugin.zip")
	if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const manifest = `{"id": "grafana-lokiexplore-app", "info": {"version": "2.4.0"}}`

func TestExtractValidArchive(t *testing.T) {
	archive := buildZip(t, map[string]string{
		"grafana-lokiexplore-app/":            "",
		"grafana-lokiexplore-app/plugin.json": manifest,
		"grafana-lokiexplore-app/module.js":   "export {}\n",
	})
	destination := t.TempDir()
	summary, err := extract(archive, destination, "grafana-lokiexplore-app", "2.4.0")
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	expected := "plugin=grafana-lokiexplore-app\nversion=2.4.0\nentries=3\nfiles=2\ndirectories=1\nbytes=" +
		"73\n"
	if summary != expected {
		t.Fatalf("summary %q, expected %q", summary, expected)
	}
	written, err := os.ReadFile(filepath.Join(destination, "grafana-lokiexplore-app", "module.js"))
	if err != nil || string(written) != "export {}\n" {
		t.Fatalf("extracted module.js content drifted: %q, %v", written, err)
	}
	info, err := os.Stat(filepath.Join(destination, "grafana-lokiexplore-app", "plugin.json"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("extracted file mode drifted: %v, %v", info, err)
	}
}

func TestExtractRejectsTraversalEntries(t *testing.T) {
	for _, name := range []string{
		"../evil.js",
		"grafana-lokiexplore-app/../../evil.js",
		"/grafana-lokiexplore-app/abs.js",
		"grafana-lokiexplore-app\\win.js",
	} {
		archive := buildZip(t, map[string]string{
			"grafana-lokiexplore-app/plugin.json": manifest,
			name:                                  "hostile",
		})
		if _, err := extract(archive, t.TempDir(), "grafana-lokiexplore-app", "2.4.0"); err == nil {
			t.Fatalf("hostile entry %q was accepted", name)
		}
	}
}

func TestExtractRejectsForeignRoot(t *testing.T) {
	archive := buildZip(t, map[string]string{
		"grafana-lokiexplore-app/plugin.json": manifest,
		"other-plugin/module.js":              "foreign",
	})
	if _, err := extract(archive, t.TempDir(), "grafana-lokiexplore-app", "2.4.0"); err == nil {
		t.Fatal("foreign top-level root was accepted")
	}
}

func TestExtractRejectsIdentityDrift(t *testing.T) {
	archive := buildZip(t, map[string]string{
		"grafana-lokiexplore-app/plugin.json": manifest,
	})
	if _, err := extract(archive, t.TempDir(), "grafana-lokiexplore-app", "9.9.9"); err == nil {
		t.Fatal("version drift was accepted")
	}
	archive = buildZip(t, map[string]string{
		"grafana-lokiexplore-app/plugin.json": `{"id": "someone-else", "info": {"version": "2.4.0"}}`,
	})
	if _, err := extract(archive, t.TempDir(), "grafana-lokiexplore-app", "2.4.0"); err == nil {
		t.Fatal("plugin id drift was accepted")
	}
}

func TestExtractRejectsMissingManifest(t *testing.T) {
	archive := buildZip(t, map[string]string{
		"grafana-lokiexplore-app/module.js": "export {}\n",
	})
	if _, err := extract(archive, t.TempDir(), "grafana-lokiexplore-app", "2.4.0"); err == nil {
		t.Fatal("archive without plugin.json was accepted")
	}
}

func TestExtractRejectsSymlinkEntries(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, err := writer.Create("grafana-lokiexplore-app/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	header := &zip.FileHeader{Name: "grafana-lokiexplore-app/link.js"}
	header.SetMode(os.ModeSymlink | 0o777)
	link, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := link.Write([]byte("/etc/passwd")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "plugin.zip")
	if err := os.WriteFile(archive, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := extract(archive, t.TempDir(), "grafana-lokiexplore-app", "2.4.0"); err == nil {
		t.Fatal("symlink entry was accepted")
	}
}
