// aigw-health-probe is a static, dependency-free health client for DHI
// runtime images that intentionally omit curl, wget, redis-cli, and shells.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 3 * time.Second
	maxHTTPBody    = 1 << 20
	maxRESPLine    = 64 << 10
	maxSecretFile  = 4 << 10
)

func usage() error {
	return errors.New(
		"usage: aigw-health-probe http|redis|metric-fixture|fixture-state [options]",
	)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "health probe failed:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "http":
		return runHTTP(args[1:])
	case "redis":
		return runRedis(args[1:])
	case "metric-fixture":
		return runMetricFixture(args[1:])
	case "fixture-state":
		return runFixtureState(args[1:])
	default:
		return usage()
	}
}

func runMetricFixture(args []string) error {
	fs := flag.NewFlagSet("metric-fixture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	address := fs.String("listen", "127.0.0.1:9101", "HTTP listen address")
	stateFile := fs.String("state-file", "", "absolute path to the fixture state file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *address == "" {
		return errors.New("metric fixture accepts flags only")
	}
	if *stateFile == "" || !filepath.IsAbs(*stateFile) {
		return errors.New("metric fixture requires an absolute --state-file")
	}
	server := &http.Server{
		Addr:              *address,
		Handler:           metricFixtureHandler(*stateFile),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve metric fixture: %w", err)
	}
	return nil
}

func metricFixtureHandler(stateFile string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(writer, "ok\n")
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		active, err := fixtureIsActive(stateFile)
		if err != nil {
			http.Error(writer, "fixture state unavailable", http.StatusInternalServerError)
			return
		}
		value := "0"
		if active {
			value = "1"
		}
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(
			writer,
			"# HELP aigw_preprod_alert_test Bounded local PreProd alert acceptance input.\n"+
				"# TYPE aigw_preprod_alert_test gauge\n"+
				"aigw_preprod_alert_test "+value+"\n",
		)
	})
	return mux
}

func fixtureIsActive(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("fixture state must be a regular file")
	}
	return true, nil
}

func runFixtureState(args []string) error {
	fs := flag.NewFlagSet("fixture-state", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateFile := fs.String("state-file", "", "absolute path to the fixture state file")
	active := fs.String("active", "", "true or false")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *stateFile == "" || !filepath.IsAbs(*stateFile) {
		return errors.New("fixture-state requires an absolute --state-file")
	}
	wanted, err := strconv.ParseBool(*active)
	if err != nil {
		return errors.New("fixture-state requires --active=true or --active=false")
	}
	if wanted {
		descriptor, createErr := os.OpenFile(
			*stateFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
		)
		if errors.Is(createErr, os.ErrExist) {
			_, inspectErr := fixtureIsActive(*stateFile)
			return inspectErr
		}
		if createErr != nil {
			return fmt.Errorf("activate fixture: %w", createErr)
		}
		return descriptor.Close()
	}
	if _, inspectErr := fixtureIsActive(*stateFile); inspectErr != nil {
		return inspectErr
	}
	if removeErr := os.Remove(*stateFile); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("deactivate fixture: %w", removeErr)
	}
	return nil
}

func runHTTP(args []string) error {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	url := fs.String("url", "", "HTTP(S) readiness URL")
	wantStatus := fs.Int("status", http.StatusOK, "required HTTP status")
	contains := fs.String("contains", "", "required response-body substring")
	timeout := fs.Duration("timeout", defaultTimeout, "total request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || fs.NArg() != 0 {
		return errors.New("http probe requires exactly one --url")
	}
	if !strings.HasPrefix(*url, "http://") && !strings.HasPrefix(*url, "https://") {
		return errors.New("http probe URL must use http:// or https://")
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("http probe timeout must be between 0 and 30s")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return fmt.Errorf("construct request: %w", err)
	}
	req.Header.Set("User-Agent", "aigw-health-probe/1")
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   *timeout,
		ResponseHeaderTimeout: *timeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not accepted by health probes")
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != *wantStatus {
		return fmt.Errorf("unexpected HTTP status %d (wanted %d)", response.StatusCode, *wantStatus)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxHTTPBody {
		return errors.New("health response exceeded 1 MiB")
	}
	if *contains != "" && !bytes.Contains(body, []byte(*contains)) {
		return errors.New("health response did not contain required marker")
	}
	return nil
}

func runRedis(args []string) error {
	fs := flag.NewFlagSet("redis", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	address := fs.String("address", "127.0.0.1:6379", "Redis TCP address")
	passwordFile := fs.String("password-file", "", "absolute path to a file containing the Redis password")
	timeout := fs.Duration("timeout", defaultTimeout, "connection and command timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *address == "" {
		return errors.New("redis probe accepts flags only")
	}
	if *passwordFile == "" || !filepath.IsAbs(*passwordFile) {
		return errors.New("redis probe requires an absolute --password-file")
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("redis probe timeout must be between 0 and 30s")
	}
	password, err := readPasswordFile(*passwordFile)
	if err != nil {
		return err
	}

	dialer := net.Dialer{Timeout: *timeout}
	connection, err := dialer.Dial("tcp", *address)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(*timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	reader := bufio.NewReaderSize(connection, maxRESPLine)
	if err := writeRESP(connection, "AUTH", password); err != nil {
		return fmt.Errorf("send AUTH: %w", err)
	}
	line, err := readRESPLine(reader)
	if err != nil {
		return fmt.Errorf("read AUTH response: %w", err)
	}
	if line != "+OK" {
		return errors.New("Redis authentication was rejected")
	}
	if err := writeRESP(connection, "PING"); err != nil {
		return fmt.Errorf("send PING: %w", err)
	}
	line, err = readRESPLine(reader)
	if err != nil {
		return fmt.Errorf("read PING response: %w", err)
	}
	if line != "+PONG" {
		return errors.New("Redis PING did not return PONG")
	}
	return nil
}

func readPasswordFile(path string) (string, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Redis password file: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return "", errors.New("Redis password path must be a regular file, not a link or special file")
	}

	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Redis password file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat Redis password file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("Redis password file must be a regular file")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return "", errors.New("Redis password file must not be accessible to other users")
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxSecretFile+1))
	if err != nil {
		return "", fmt.Errorf("read Redis password file: %w", err)
	}
	if len(contents) > maxSecretFile {
		return "", errors.New("Redis password file exceeds 4 KiB")
	}
	contents = bytes.TrimSuffix(contents, []byte{'\n'})
	if len(contents) == 0 {
		return "", errors.New("Redis password file is empty")
	}
	if bytes.IndexAny(contents, "\x00\r\n") >= 0 {
		return "", errors.New("Redis password file contains an invalid line break or NUL")
	}
	return string(contents), nil
}

func writeRESP(writer io.Writer, values ...string) error {
	var request strings.Builder
	request.WriteByte('*')
	request.WriteString(strconv.Itoa(len(values)))
	request.WriteString("\r\n")
	for _, value := range values {
		request.WriteByte('$')
		request.WriteString(strconv.Itoa(len(value)))
		request.WriteString("\r\n")
		request.WriteString(value)
		request.WriteString("\r\n")
	}
	_, err := io.WriteString(writer, request.String())
	return err
}

func readRESPLine(reader *bufio.Reader) (string, error) {
	lineBytes, err := reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(lineBytes) > maxRESPLine {
		return "", errors.New("Redis response line exceeded 64 KiB")
	}
	line := string(lineBytes)
	if !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("malformed Redis response")
	}
	line = strings.TrimSuffix(line, "\r\n")
	if strings.HasPrefix(line, "-") {
		return "", errors.New("Redis returned an error")
	}
	return line, nil
}
