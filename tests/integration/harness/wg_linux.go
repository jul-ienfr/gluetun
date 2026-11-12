//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultWireGuardPort    = 51820
	defaultWireGuardMTU     = 1420
	defaultKeepalive        = 5
	defaultWireGuardTunnel  = "10.66.0.1/24"
	defaultWireGuardPeer    = "10.66.0.2/32"
	defaultWireGuardEcho    = "vpn-wg-test:51820"
	wireGuardRouteCIDR      = "10.66.0.0/24"
	wireGuardClientIface    = "wgclient0"
	wireGuardConfigDirMode  = 0o750
	wireGuardConfigFileMode = 0o600
	wireGuardProbeDeadline  = 10 * time.Second
	wireGuardProbeInterval  = 500 * time.Millisecond
	wireGuardReadTimeout    = 5 * time.Second
)

type wireGuardSettings struct {
	iface      string
	listen     string
	tunnel     string
	peer       string
	httpListen string
	ip         string
	endpoint   string
	clientOut  string
	mtu        int
	keepalive  int
}

func parseWireGuardSettings(args []string) (settings wireGuardSettings, err error) {
	flags := flag.NewFlagSet("wg", flag.ContinueOnError)
	flags.StringVar(&settings.iface, "iface", "wgtest0",
		"TUN interface name")
	flags.StringVar(&settings.listen, "listen", "0.0.0.0:51820",
		"WireGuard UDP listen address")
	flags.StringVar(&settings.tunnel, "tunnel", defaultWireGuardTunnel,
		"server tunnel address with prefix")
	flags.StringVar(&settings.peer, "peer", defaultWireGuardPeer,
		"allowed client tunnel address with prefix")
	flags.StringVar(&settings.httpListen, "http-listen", "0.0.0.0:8080",
		"HTTP echo listen address")
	flags.StringVar(&settings.ip, "ip", "203.0.113.20",
		"IP reported by the HTTP echo")
	flags.StringVar(&settings.endpoint, "endpoint", "",
		"client endpoint host:port written to the client configuration")
	flags.StringVar(&settings.clientOut, "client-out", "/shared/wg0.conf",
		"path to write the WireGuard client configuration")
	flags.IntVar(&settings.mtu, "mtu", defaultWireGuardMTU, "tunnel MTU")
	flags.IntVar(&settings.keepalive, "keepalive", defaultKeepalive,
		"client persistent keepalive interval in seconds")

	err = flags.Parse(args)
	if err != nil {
		return settings, err
	}

	if settings.endpoint == "" {
		settings.endpoint = defaultWireGuardEcho
	}
	if settings.ip != "auto" {
		ip := net.ParseIP(settings.ip)
		if ip == nil || ip.To4() == nil {
			return settings, fmt.Errorf("invalid IPv4 address %q", settings.ip)
		}
	}

	return settings, nil
}

func runWireGuard(args []string) (err error) {
	settings, err := parseWireGuardSettings(args)
	if err != nil {
		return err
	}

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating client key: %w", err)
	}
	serverPublicKey := serverPrivateKey.PublicKey()
	clientPublicKey := clientPrivateKey.PublicKey()

	tunDevice, err := tun.CreateTUN(settings.iface, settings.mtu)
	if err != nil {
		return fmt.Errorf("creating TUN device %s: %w", settings.iface, err)
	}
	defer tunDevice.Close()

	logger := device.NewLogger(device.LogLevelError, "wg-test: ")
	wireGuardDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	defer wireGuardDevice.Close()

	ipcConfig := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=%s\n",
		hex.EncodeToString(serverPrivateKey[:]),
		portFromAddress(settings.listen),
		hex.EncodeToString(clientPublicKey[:]),
		settings.peer,
	)
	err = wireGuardDevice.IpcSet(ipcConfig)
	if err != nil {
		return fmt.Errorf("configuring WireGuard device: %w", err)
	}

	err = wireGuardDevice.Up()
	if err != nil {
		return fmt.Errorf("bringing WireGuard device up: %w", err)
	}

	err = configureInterface(settings.iface, settings.tunnel)
	if err != nil {
		return err
	}

	err = writeWireGuardClientConfig(settings, clientPrivateKey,
		serverPublicKey, clientPublicKey)
	if err != nil {
		return err
	}

	echoServer := &http.Server{
		Addr: settings.httpListen,
		Handler: newEchoHandler(echoSettings{
			listen: settings.httpListen,
			name:   "vpn-wg-test",
			ip:     settings.ip,
			status: http.StatusServiceUnavailable,
			body:   "ok",
		}),
		ReadHeaderTimeout: wireGuardReadTimeout,
	}
	errorsChannel := make(chan error, 1)
	go func() {
		errorsChannel <- echoServer.ListenAndServe()
	}()

	fmt.Printf("wg: %s listening on %s, tunnel %s, echo on %s\n",
		settings.iface, settings.listen, settings.tunnel, settings.httpListen)
	fmt.Printf("wg: client configuration written to %s\n", settings.clientOut)
	if settings.clientOut != "" {
		fmt.Printf("wg: client public key %s\n", clientPublicKey.String())
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signalChannel:
		fmt.Printf("wg: received %s, shutting down\n", sig)
		_ = echoServer.Close()
		return nil
	case err := <-errorsChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serving HTTP: %w", err)
	}
}

func portFromAddress(address string) int {
	_, portString, err := net.SplitHostPort(address)
	if err != nil {
		return defaultWireGuardPort
	}
	port := 0
	_, _ = fmt.Sscanf(portString, "%d", &port)
	if port == 0 {
		return defaultWireGuardPort
	}
	return port
}

func configureInterface(iface, tunnelAddress string) (err error) {
	commands := [][]string{
		{"ip", "addr", "add", tunnelAddress, "dev", iface},
		{"ip", "link", "set", iface, "up"},
	}
	for _, arguments := range commands {
		//nolint:gosec // interface names and addresses come from harness flags
		command := exec.CommandContext(context.Background(), arguments[0], arguments[1:]...)
		output, err := command.CombinedOutput()
		if err != nil {
			trimmed := strings.TrimSpace(string(output))
			// Address already assigned is fine on restart.
			if strings.Contains(trimmed, "File exists") ||
				strings.Contains(trimmed, "already assigned") {
				continue
			}
			return fmt.Errorf("running %s: %w: %s",
				strings.Join(arguments, " "), err, trimmed)
		}
	}
	return nil
}

func writeWireGuardClientConfig(settings wireGuardSettings,
	clientPrivateKey, serverPublicKey, clientPublicKey wgtypes.Key,
) (err error,
) {
	config := fmt.Sprintf(`[Interface]
# Client public key: %s
PrivateKey = %s
Address = %s
MTU = %d

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`,
		clientPublicKey.String(),
		clientPrivateKey.String(),
		settings.peer,
		settings.mtu,
		serverPublicKey.String(),
		settings.endpoint,
		wireGuardRouteCIDR,
		settings.keepalive,
	)

	err = os.MkdirAll(filepathDir(settings.clientOut), wireGuardConfigDirMode)
	if err != nil {
		return fmt.Errorf("creating client configuration directory: %w", err)
	}
	err = os.WriteFile(settings.clientOut, []byte(config),
		wireGuardConfigFileMode)
	if err != nil {
		return fmt.Errorf("writing client configuration: %w", err)
	}
	return nil
}

func filepathDir(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index <= 0 {
		return "."
	}
	return path[:index]
}

type wireGuardClientConfig struct {
	privateKey      wgtypes.Key
	address         string
	serverPublicKey wgtypes.Key
	endpoint        string
	allowedIP       string
}

func parseWireGuardClientConfig(path string) (config wireGuardClientConfig,
	err error,
) {
	content, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("reading %s: %w", path, err)
	}

	section := ""
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch section {
		case "[Interface]":
			switch key {
			case "PrivateKey":
				config.privateKey, err = wgtypes.ParseKey(value)
				if err != nil {
					return config, fmt.Errorf("parsing PrivateKey: %w", err)
				}
			case "Address":
				config.address = strings.TrimSpace(strings.Split(value, ",")[0])
			}
		case "[Peer]":
			switch key {
			case "PublicKey":
				config.serverPublicKey, err = wgtypes.ParseKey(value)
				if err != nil {
					return config, fmt.Errorf("parsing PublicKey: %w", err)
				}
			case "Endpoint":
				config.endpoint = value
			case "AllowedIPs":
				config.allowedIP = strings.TrimSpace(strings.Split(value, ",")[0])
			}
		}
	}

	switch {
	case config.privateKey == (wgtypes.Key{}):
		return config, errors.New("missing PrivateKey in [Interface]")
	case config.address == "":
		return config, errors.New("missing Address in [Interface]")
	case config.serverPublicKey == (wgtypes.Key{}):
		return config, errors.New("missing PublicKey in [Peer]")
	case config.endpoint == "":
		return config, errors.New("missing Endpoint in [Peer]")
	case config.allowedIP == "":
		return config, errors.New("missing AllowedIPs in [Peer]")
	}

	return config, nil
}

func checkWireGuardTunnel(settings checkSettings) (err error) {
	config, err := parseWireGuardClientConfig(settings.wgConfig)
	if err != nil {
		return err
	}

	interfaceName := wireGuardClientIface
	tunDevice, err := tun.CreateTUN(interfaceName, defaultWireGuardMTU)
	if err != nil {
		return fmt.Errorf("creating TUN device %s: %w", interfaceName, err)
	}
	defer tunDevice.Close()

	logger := device.NewLogger(device.LogLevelError, "wg-client: ")
	wireGuardDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	defer wireGuardDevice.Close()

	endpointAddress, err := net.ResolveUDPAddr("udp", config.endpoint)
	if err != nil {
		return fmt.Errorf("resolving endpoint %s: %w", config.endpoint, err)
	}

	ipcConfig := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
allowed_ip=%s
persistent_keepalive_interval=5
`,
		hex.EncodeToString(config.privateKey[:]),
		hex.EncodeToString(config.serverPublicKey[:]),
		endpointAddress.String(),
		config.allowedIP,
	)
	err = wireGuardDevice.IpcSet(ipcConfig)
	if err != nil {
		return fmt.Errorf("configuring WireGuard client: %w", err)
	}
	err = wireGuardDevice.Up()
	if err != nil {
		return fmt.Errorf("bringing WireGuard client up: %w", err)
	}

	err = configureInterface(interfaceName, config.address)
	if err != nil {
		return err
	}
	//nolint:gosec // route arguments come from the generated client configuration
	command := exec.CommandContext(context.Background(), "ip", "route", "add",
		config.allowedIP, "dev", interfaceName)
	routeOutput, err := command.CombinedOutput()
	if err != nil && !strings.Contains(string(routeOutput), "File exists") {
		return fmt.Errorf("adding route %s: %w: %s", config.allowedIP, err,
			strings.TrimSpace(string(routeOutput)))
	}

	deadline := time.Now().Add(wireGuardProbeDeadline)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = checkEcho(settings, settings.wgTunnelURL, settings.wgIP)
		if lastErr == nil {
			return nil
		}
		time.Sleep(wireGuardProbeInterval)
	}
	return lastErr
}
