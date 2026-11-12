package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultCheckWait    = 30 * time.Second
	defaultCheckTimeout = 3 * time.Second
	checkRetryInterval  = 500 * time.Millisecond
	maxResponseBytes    = 1 << 20
)

type checkSettings struct {
	plain       string
	dot         string
	dotName     string
	caPath      string
	queryName   string
	echoes      []string
	expectIPs   []string
	wgConfig    string
	wgEcho      string
	wgIP        string
	wgTunnel    bool
	wgTunnelURL string
	wait        time.Duration
	timeout     time.Duration
}

func parseCheckSettings(args []string) (settings checkSettings, err error) {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.StringVar(&settings.plain, "plain", "plain:53",
		"plain DNS server address")
	flags.StringVar(&settings.dot, "dot", "dot:853",
		"DNS over TLS server address")
	flags.StringVar(&settings.dotName, "dot-name", "dot.test",
		"DNS over TLS server name")
	flags.StringVar(&settings.caPath, "ca", "/certs/ca.crt",
		"CA certificate used to verify the DoT server")
	flags.StringVar(&settings.queryName, "query", "verify.test",
		"DNS name queried against both DNS servers")
	echoes := flags.String("echo", "",
		"comma separated HTTP echo base URLs")
	expectedIPs := flags.String("expect-ips", "",
		"comma separated IPs expected from each echo, in order")
	flags.StringVar(&settings.wgConfig, "wg-config", "",
		"optional WireGuard client configuration to validate")
	flags.StringVar(&settings.wgEcho, "wg-echo", "",
		"optional WireGuard echo base URL to validate")
	flags.StringVar(&settings.wgIP, "wg-ip", "",
		"IP expected from the WireGuard echo")
	flags.BoolVar(&settings.wgTunnel, "wg-tunnel", false,
		"start a WireGuard client and verify traffic through the tunnel")
	flags.StringVar(&settings.wgTunnelURL, "wg-tunnel-url",
		"http://10.66.0.1:8080",
		"HTTP echo URL reached through the WireGuard tunnel")
	flags.DurationVar(&settings.wait, "wait", defaultCheckWait,
		"maximum time to wait for services to become ready")
	flags.DurationVar(&settings.timeout, "timeout", defaultCheckTimeout,
		"per-request timeout")

	err = flags.Parse(args)
	if err != nil {
		return settings, err
	}

	settings.echoes = splitNonEmpty(*echoes)
	settings.expectIPs = splitNonEmpty(*expectedIPs)
	if len(settings.expectIPs) > 0 && len(settings.expectIPs) != len(settings.echoes) {
		return settings, fmt.Errorf("%d expected IPs for %d echoes",
			len(settings.expectIPs), len(settings.echoes))
	}
	return settings, nil
}

func splitNonEmpty(value string) (parts []string) {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func runCheck(args []string) (err error) {
	settings, err := parseCheckSettings(args)
	if err != nil {
		return err
	}

	steps := []struct {
		name string
		run  func() error
	}{
		{
			name: "plain DNS answers " + settings.queryName,
			run: func() error {
				return checkDNS(settings, false)
			},
		},
		{
			name: "DoT answers " + settings.queryName,
			run: func() error {
				return checkDNS(settings, true)
			},
		},
		{
			name: "plain DNS SERVFAIL injection",
			run: func() error {
				return checkServfail(settings)
			},
		},
	}

	for index, echoURL := range settings.echoes {
		expectedIP := ""
		if len(settings.expectIPs) > 0 {
			expectedIP = settings.expectIPs[index]
		}
		steps = append(steps, struct {
			name string
			run  func() error
		}{
			name: "HTTP echo " + echoURL,
			run: func() error {
				return checkEcho(settings, echoURL, expectedIP)
			},
		})
	}

	if settings.wgConfig != "" {
		steps = append(steps, struct {
			name string
			run  func() error
		}{
			name: "WireGuard client configuration",
			run: func() error {
				return checkWireGuardConfig(settings.wgConfig)
			},
		})
	}

	if settings.wgTunnel {
		steps = append(steps, struct {
			name string
			run  func() error
		}{
			name: "WireGuard tunnel " + settings.wgTunnelURL,
			run: func() error {
				return checkWireGuardTunnel(settings)
			},
		})
	}

	if settings.wgEcho != "" {
		steps = append(steps, struct {
			name string
			run  func() error
		}{
			name: "WireGuard echo " + settings.wgEcho,
			run: func() error {
				return checkEcho(settings, settings.wgEcho, settings.wgIP)
			},
		})
	}

	for _, step := range steps {
		err := waitFor(settings.wait, step.run)
		if err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		fmt.Printf("check: ok %s\n", step.name)
	}

	fmt.Println("check: all harness services are ready")
	return nil
}

func waitFor(timeout time.Duration, check func() error) (err error) {
	deadline := time.Now().Add(timeout)
	for {
		err = check()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(checkRetryInterval)
	}
}

func checkDNS(settings checkSettings, overTLS bool) (err error) {
	address := settings.plain
	client := &dns.Client{Net: "udp", Timeout: settings.timeout}
	if overTLS {
		address = settings.dot
		tlsConfig, err := loadTLSConfig(settings.caPath, settings.dotName)
		if err != nil {
			return err
		}
		client.Net = "tcp-tls"
		client.TLSConfig = tlsConfig
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(settings.queryName), dns.TypeA)

	response, _, err := client.Exchange(message, address)
	if err != nil {
		return err
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("unexpected rcode %s", dns.RcodeToString[response.Rcode])
	}
	if firstA(response) == "" {
		return errors.New("no A record in response")
	}
	return nil
}

func checkServfail(settings checkSettings) (err error) {
	client := &dns.Client{Net: "udp", Timeout: settings.timeout}
	message := new(dns.Msg)
	message.SetQuestion("servfail.test.", dns.TypeA)

	response, _, err := client.Exchange(message, settings.plain)
	if err != nil {
		return err
	}
	if response.Rcode != dns.RcodeServerFailure {
		return fmt.Errorf("expected SERVFAIL, got %s",
			dns.RcodeToString[response.Rcode])
	}
	return nil
}

func firstA(response *dns.Msg) string {
	for _, answer := range response.Answer {
		record, ok := answer.(*dns.A)
		if ok {
			return record.A.String()
		}
	}
	return ""
}

func loadTLSConfig(caPath, serverName string) (tlsConfig *tls.Config, err error) {
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificate found in %s", caPath)
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: serverName,
	}, nil
}

func httpGet(client *http.Client, url string) (response *http.Response, err error) {
	//nolint:gosec // harness URLs are configured by the test
	request, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // harness URLs are configured by the test
	return client.Do(request)
}

func checkEcho(settings checkSettings, baseURL, expectedIP string) (err error) {
	client := &http.Client{Timeout: settings.timeout}
	response, err := httpGet(client, strings.TrimSuffix(baseURL, "/")+"/ip")
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}

	var decoded struct {
		IP     string `json:"ip"`
		Source string `json:"source"`
	}
	err = json.Unmarshal(body, &decoded)
	if err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	if decoded.IP == "" {
		return errors.New("empty IP in response")
	}
	if expectedIP != "" && decoded.IP != expectedIP {
		return fmt.Errorf("expected IP %s, got %s", expectedIP, decoded.IP)
	}

	canaryResponse, err := httpGet(client, strings.TrimSuffix(baseURL, "/")+"/canary")
	if err != nil {
		return err
	}
	defer canaryResponse.Body.Close()
	canaryBody, err := io.ReadAll(io.LimitReader(canaryResponse.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if canaryResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("canary returned status %d", canaryResponse.StatusCode)
	}
	if strings.TrimSpace(string(canaryBody)) == "" {
		return errors.New("empty canary body")
	}

	return nil
}

func checkWireGuardConfig(path string) (err error) {
	//nolint:gosec // configuration path is explicitly configured by the test
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	text := string(content)
	required := []string{
		"[Interface]", "PrivateKey", "[Peer]", "PublicKey",
		"AllowedIPs", "Endpoint",
	}
	for _, part := range required {
		if !strings.Contains(text, part) {
			return fmt.Errorf("%s is missing %q", path, part)
		}
	}
	return nil
}
