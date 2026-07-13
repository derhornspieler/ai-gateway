package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"status":"UP"}`))
	}))
	defer server.Close()
	if err := run([]string{"http", "--url", server.URL, "--contains", `"UP"`}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"http", "--url", server.URL, "--contains", "missing"}); err == nil {
		t.Fatal("expected missing marker to fail")
	}
}

func TestHTTPProbeRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/ready", http.StatusFound)
	}))
	defer server.Close()
	if err := run([]string{"http", "--url", server.URL}); err == nil {
		t.Fatal("expected redirect to fail")
	}
}

func TestRedisProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	passwordPath := filepath.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(passwordPath, []byte("correct-horse-battery-staple\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		first, _ := io.ReadAll(io.LimitReader(reader, int64(len("*2\r\n$4\r\nAUTH\r\n$28\r\ncorrect-horse-battery-staple\r\n"))))
		if !strings.Contains(string(first), "AUTH") || !strings.Contains(string(first), "correct-horse-battery-staple") {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, _ = io.WriteString(connection, "+OK\r\n")
		second := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
		if _, readErr := io.ReadFull(reader, second); readErr != nil {
			done <- readErr
			return
		}
		_, _ = io.WriteString(connection, "+PONG\r\n")
		done <- nil
	}()
	if err := run([]string{"redis", "--address", listener.Addr().String(), "--password-file", passwordPath}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRedisProbeRequiresPrivateRegularPasswordFile(t *testing.T) {
	directory := t.TempDir()
	worldReadable := filepath.Join(directory, "world-readable")
	if err := os.WriteFile(worldReadable, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(worldReadable); err == nil {
		t.Fatal("expected a world-readable password file to fail")
	}

	multiline := filepath.Join(directory, "multiline")
	if err := os.WriteFile(multiline, []byte("secret\ninjected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(multiline); err == nil {
		t.Fatal("expected a multiline password file to fail")
	}

	link := filepath.Join(directory, "password-link")
	private := filepath.Join(directory, "private")
	if err := os.WriteFile(private, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(link); err == nil {
		t.Fatal("expected a symlinked password file to fail")
	}

	if err := run([]string{"redis", "--password-env", "REDIS_PASSWORD"}); err == nil {
		t.Fatal("legacy environment-secret option must remain unsupported")
	}
}
