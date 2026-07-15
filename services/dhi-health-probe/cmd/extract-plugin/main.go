// Command extract-plugin safely unpacks a reviewed, checksum-pinned Grafana
// plugin archive into an image build stage. It is stdlib-only and runs under
// RUN --network=none inside services/dhi-health-probe/Dockerfile.grafana.
//
// The zip has already been fetched with a mandatory BuildKit --checksum and
// re-verified with sha256sum, so this tool's job is structural: refuse every
// unsafe archive shape (traversal, absolute paths, links, foreign roots,
// duplicates, unbounded growth), prove the plugin identity/version match the
// reviewed pin, and emit a deterministic inventory summary the Dockerfile
// asserts byte-for-byte.
package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	maxEntries    = 4096
	maxTotalBytes = 128 << 20 // 128 MiB uncompressed
)

type pluginManifest struct {
	ID   string `json:"id"`
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "extract-plugin: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 5 {
		fail("usage: extract-plugin ZIP DEST PLUGIN_ID VERSION")
	}
	archive, destination, pluginID, version := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	summary, err := extract(archive, destination, pluginID, version)
	if err != nil {
		fail("%v", err)
	}
	fmt.Print(summary)
}

// safeRelative rejects every entry name that could escape the plugin root or
// smuggle unexpected content, and returns the cleaned relative path.
func safeRelative(name, pluginID string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned == "." {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	if cleaned != pluginID && !strings.HasPrefix(cleaned, pluginID+"/") {
		return "", fmt.Errorf("archive entry %q is outside the %s root", name, pluginID)
	}
	return cleaned, nil
}

func extract(archive, destination, pluginID, version string) (string, error) {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", archive, err)
	}
	defer reader.Close()

	if len(reader.File) == 0 {
		return "", fmt.Errorf("archive %s is empty", archive)
	}
	if len(reader.File) > maxEntries {
		return "", fmt.Errorf("archive holds %d entries; the reviewed bound is %d", len(reader.File), maxEntries)
	}

	seen := make(map[string]bool, len(reader.File))
	var files, directories int
	var totalBytes int64
	for _, entry := range reader.File {
		cleaned, err := safeRelative(entry.Name, pluginID)
		if err != nil {
			return "", err
		}
		if seen[cleaned] {
			return "", fmt.Errorf("duplicate archive entry %q", cleaned)
		}
		seen[cleaned] = true

		target := filepath.Join(destination, filepath.FromSlash(cleaned))
		mode := entry.Mode()
		switch {
		case mode.IsDir():
			directories++
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case mode.IsRegular():
			files++
			totalBytes += int64(entry.UncompressedSize64)
			if totalBytes > maxTotalBytes {
				return "", fmt.Errorf("archive exceeds the reviewed %d-byte bound", int64(maxTotalBytes))
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			if err := writeFile(target, entry); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("archive entry %q is neither a regular file nor a directory", cleaned)
		}
	}

	manifestPath := filepath.Join(destination, pluginID, "plugin.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("plugin manifest missing: %w", err)
	}
	var manifest pluginManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", fmt.Errorf("plugin manifest is not valid JSON: %w", err)
	}
	if manifest.ID != pluginID {
		return "", fmt.Errorf("plugin id %q does not match the reviewed pin %q", manifest.ID, pluginID)
	}
	if manifest.Info.Version != version {
		return "", fmt.Errorf("plugin version %q does not match the reviewed pin %q", manifest.Info.Version, version)
	}

	return fmt.Sprintf(
		"plugin=%s\nversion=%s\nentries=%d\nfiles=%d\ndirectories=%d\nbytes=%d\n",
		pluginID, version, files+directories, files, directories, totalBytes,
	), nil
}

func writeFile(target string, entry *zip.File) error {
	source, err := entry.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	// Copy at most the declared size plus one byte: a decompressed stream
	// that outgrows its own directory entry is a hostile archive.
	written, err := io.Copy(out, io.LimitReader(source, int64(entry.UncompressedSize64)+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if written != int64(entry.UncompressedSize64) {
		return fmt.Errorf("archive entry %q decompressed to %d bytes, expected %d", entry.Name, written, entry.UncompressedSize64)
	}
	return nil
}
