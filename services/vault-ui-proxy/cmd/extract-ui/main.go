// Command extract-ui recovers the exact Vault 2.0.3 web_ui embed filesystem
// from a HashiCorp-signed release binary without executing that binary.
// The private Go embed layout is intentionally version-specific; the Docker
// build additionally pins entry/file/byte counts and the full output manifest.
package main

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	filesSymbol = "github.com/hashicorp/vault/http.content.files"
	entrySize   = uint64(48)
)

type section struct {
	address uint64
	size    uint64
	reader  io.ReaderAt
}

type image struct {
	order    binary.ByteOrder
	sections []section
	symbols  map[string]uint64
	close    func() error
}

type manifestEntry struct {
	name string
	size int
	hash string
}

func fail(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func openImage(filename string) (*image, error) {
	if file, err := macho.Open(filename); err == nil {
		if file.Magic != macho.Magic64 || file.Symtab == nil {
			_ = file.Close()
			return nil, errors.New("expected a 64-bit Mach-O with a symbol table")
		}
		image := &image{
			order:   file.ByteOrder,
			symbols: make(map[string]uint64),
			close:   file.Close,
		}
		for _, fileSection := range file.Sections {
			image.sections = append(image.sections, section{
				address: fileSection.Addr,
				size:    fileSection.Size,
				reader:  fileSection,
			})
		}
		for _, symbol := range file.Symtab.Syms {
			image.symbols[symbol.Name] = symbol.Value
		}
		return image, nil
	}
	if file, err := elf.Open(filename); err == nil {
		if file.Class != elf.ELFCLASS64 {
			_ = file.Close()
			return nil, errors.New("expected a 64-bit ELF")
		}
		image := &image{
			order:   file.ByteOrder,
			symbols: make(map[string]uint64),
			close:   file.Close,
		}
		for _, fileSection := range file.Sections {
			if fileSection.Type == elf.SHT_NOBITS {
				continue
			}
			image.sections = append(image.sections, section{
				address: fileSection.Addr,
				size:    fileSection.Size,
				reader:  fileSection,
			})
		}
		symbols, err := file.Symbols()
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("read ELF symbols: %w", err)
		}
		for _, symbol := range symbols {
			image.symbols[symbol.Name] = symbol.Value
		}
		return image, nil
	}
	return nil, errors.New("input is not a supported 64-bit Mach-O or ELF")
}

func (image *image) readVirtualAddress(address, size uint64) ([]byte, error) {
	if size > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("oversize read: %d", size)
	}
	for _, section := range image.sections {
		if address >= section.address && size <= section.size &&
			address-section.address <= section.size-size {
			content := make([]byte, int(size))
			_, err := section.reader.ReadAt(content, int64(address-section.address))
			if err != nil && err != io.EOF {
				return nil, err
			}
			return content, nil
		}
	}
	return nil, fmt.Errorf("virtual address %#x+%d is not file-backed", address, size)
}

func (image *image) uint64(content []byte, offset int) uint64 {
	return image.order.Uint64(content[offset : offset+8])
}

func compilerHash(content []byte) [16]byte {
	var full [32]byte
	if len(content) <= 1024 {
		full = sha256.Sum256(content)
		full[0] ^= 0xff
	} else {
		digest := sha256.New()
		_, _ = digest.Write([]byte{1})
		_, _ = digest.Write(content)
		copy(full[:], digest.Sum(nil))
	}
	var short [16]byte
	copy(short[:], full[:16])
	return short
}

func safeDestination(root, relative string) (string, error) {
	clean := strings.TrimSuffix(relative, "/")
	if clean == "" {
		return root, nil
	}
	if clean == "." || !fs.ValidPath(clean) || strings.Contains(clean, `\`) {
		return "", fmt.Errorf("invalid embedded path %q", relative)
	}
	destination := filepath.Join(root, filepath.FromSlash(clean))
	relativeDestination, err := filepath.Rel(root, destination)
	if err != nil || relativeDestination == ".." ||
		strings.HasPrefix(relativeDestination, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes output root: %q", relative)
	}
	return destination, nil
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: %s VAULT_BINARY OUTPUT_DIR", os.Args[0])
	}
	binaryPath, outputRoot := os.Args[1], os.Args[2]
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		fail("output directory must not exist: %s", outputRoot)
	}
	image, err := openImage(binaryPath)
	if err != nil {
		fail("open executable: %v", err)
	}
	defer image.close()
	symbolAddress := image.symbols[filesSymbol]
	if symbolAddress == 0 {
		fail("required symbol not found: %s", filesSymbol)
	}
	header, err := image.readVirtualAddress(symbolAddress, 24)
	if err != nil {
		fail("read embed slice header: %v", err)
	}
	arrayAddress := image.uint64(header, 0)
	count := image.uint64(header, 8)
	capacity := image.uint64(header, 16)
	if count == 0 || count != capacity || count > 100000 {
		fail("invalid embed slice len/cap: %d/%d", count, capacity)
	}
	if err := os.Mkdir(outputRoot, 0o755); err != nil {
		fail("create output: %v", err)
	}
	manifest := make([]manifestEntry, 0, count)
	seen := make(map[string]struct{}, count)
	directories := 0
	for index := uint64(0); index < count; index++ {
		raw, err := image.readVirtualAddress(arrayAddress+index*entrySize, entrySize)
		if err != nil {
			fail("read embed entry %d: %v", index, err)
		}
		nameAddress, nameSize := image.uint64(raw, 0), image.uint64(raw, 8)
		dataAddress, dataSize := image.uint64(raw, 16), image.uint64(raw, 24)
		nameBytes, err := image.readVirtualAddress(nameAddress, nameSize)
		if err != nil {
			fail("read entry %d name: %v", index, err)
		}
		name := string(nameBytes)
		if _, duplicate := seen[name]; duplicate {
			fail("duplicate embedded path: %s", name)
		}
		seen[name] = struct{}{}
		if name != "web_ui/" && !strings.HasPrefix(name, "web_ui/") {
			fail("unexpected embedded root: %s", name)
		}
		relative := strings.TrimPrefix(name, "web_ui/")
		destination, err := safeDestination(outputRoot, relative)
		if err != nil {
			fail("unsafe entry: %v", err)
		}
		if strings.HasSuffix(name, "/") {
			if dataAddress != 0 || dataSize != 0 ||
				!allZero(raw[32:48]) {
				fail("malformed directory entry: %s", name)
			}
			if err := os.MkdirAll(destination, 0o755); err != nil {
				fail("create directory %s: %v", relative, err)
			}
			directories++
			continue
		}
		content, err := image.readVirtualAddress(dataAddress, dataSize)
		if err != nil {
			fail("read data for %s: %v", name, err)
		}
		expected := compilerHash(content)
		if !equalBytes(expected[:], raw[32:48]) {
			fail("compiler content hash mismatch: %s", name)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			fail("create parent for %s: %v", relative, err)
		}
		if err := os.WriteFile(destination, content, 0o644); err != nil {
			fail("write %s: %v", relative, err)
		}
		digest := sha256.Sum256(content)
		manifest = append(manifest, manifestEntry{
			name: relative,
			size: len(content),
			hash: hex.EncodeToString(digest[:]),
		})
	}
	sort.Slice(manifest, func(left, right int) bool {
		return manifest[left].name < manifest[right].name
	})
	manifestPath := outputRoot + ".MANIFEST.sha256"
	manifestFile, err := os.OpenFile(manifestPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fail("create manifest: %v", err)
	}
	total := 0
	for _, entry := range manifest {
		if _, err := fmt.Fprintf(manifestFile, "%s  %s\n", entry.hash, entry.name); err != nil {
			fail("write manifest: %v", err)
		}
		total += entry.size
	}
	if err := manifestFile.Close(); err != nil {
		fail("close manifest: %v", err)
	}
	fmt.Printf(
		"symbol=%s\nentries=%d\ndirectories=%d\nfiles=%d\nbytes=%d\nhashes_verified=%d\n",
		filesSymbol, count, directories, len(manifest), total, len(manifest),
	)
}

func allZero(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
