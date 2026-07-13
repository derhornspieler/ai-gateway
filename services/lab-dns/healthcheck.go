package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--assert-no-egress" {
		assertNoEgress(os.Args[2])
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "invalid healthcheck arguments")
		os.Exit(2)
	}

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://127.0.0.1:8080/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "CoreDNS health endpoint unavailable")
		os.Exit(1)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16))
	if err != nil || response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "OK" {
		fmt.Fprintln(os.Stderr, "CoreDNS health endpoint unhealthy")
		os.Exit(1)
	}
}

func assertNoEgress(target string) {
	if net.ParseIP(target) == nil {
		fmt.Fprintln(os.Stderr, "invalid egress-test address")
		os.Exit(2)
	}

	// A valid recursive A query. UDP "connect" alone is not evidence because
	// it succeeds before a packet is delivered; write and require no response.
	query := make([]byte, 0, 29)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xa19e)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)
	query = append(query, header...)
	query = append(query, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	query = append(query, 0, 1, 0, 1)

	udp, err := net.DialTimeout("udp", net.JoinHostPort(target, "53"), time.Second)
	if err == nil {
		_ = udp.SetDeadline(time.Now().Add(time.Second))
		if _, err = udp.Write(query); err == nil {
			response := make([]byte, 512)
			if _, err = udp.Read(response); err == nil {
				_ = udp.Close()
				fmt.Fprintln(os.Stderr, "outbound UDP DNS unexpectedly succeeded")
				os.Exit(1)
			}
		}
		_ = udp.Close()
	}

	tcp, err := net.DialTimeout("tcp", net.JoinHostPort(target, "53"), time.Second)
	if err == nil {
		_ = tcp.Close()
		fmt.Fprintln(os.Stderr, "outbound TCP unexpectedly succeeded")
		os.Exit(1)
	}

	// The runtime has CAP_NET_RAW removed. Opening an ICMP socket must fail
	// before any echo request can leave the namespace.
	icmp, err := net.DialTimeout("ip4:icmp", target, time.Second)
	if err == nil {
		_ = icmp.Close()
		fmt.Fprintln(os.Stderr, "outbound ICMP socket unexpectedly succeeded")
		os.Exit(1)
	}
}
