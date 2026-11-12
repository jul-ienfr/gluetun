package ladder

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultDoTPort      = "853"
	defaultDoHPort      = "443"
	defaultPlainPort    = "53"
	defaultHTTPTimeout  = 5 * time.Second
	maxDoHResponseBytes = 64 * 1024
)

// NetExchanger performs real DNS exchanges for each ladder transport.
type NetExchanger struct {
	mutex      sync.Mutex
	dohClients map[string]*http.Client
	timeout    time.Duration
}

// NewNetExchanger creates a network-backed ladder exchanger.
func NewNetExchanger() *NetExchanger {
	return &NetExchanger{
		dohClients: make(map[string]*http.Client),
		timeout:    defaultHTTPTimeout,
	}
}

// Exchange sends one DNS request over the tier transport.
func (e *NetExchanger) Exchange(ctx context.Context, tierType TierType,
	endpoint Endpoint, request *dns.Msg, tcp bool,
) (*dns.Msg, error) {
	switch tierType {
	case TierPlain:
		address, err := addressWithPort(endpoint.Address, defaultPlainPort)
		if err != nil {
			return nil, fmt.Errorf("plain DNS endpoint address: %w", err)
		}
		return exchangeClient(ctx, address, plainNetwork(tcp), nil, request)
	case TierDoT:
		if endpoint.TLSName == "" {
			return nil, fmt.Errorf("DoT endpoint %s has no TLS server name",
				endpoint.Address)
		}
		address, err := addressWithPort(endpoint.Address, defaultDoTPort)
		if err != nil {
			return nil, fmt.Errorf("DoT endpoint address: %w", err)
		}
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: endpoint.TLSName,
		}
		return exchangeClient(ctx, address, "tcp-tls", tlsConfig, request)
	case TierDoH:
		return e.exchangeDoH(ctx, endpoint, request)
	default:
		return nil, fmt.Errorf("unknown DNS tier %q", tierType)
	}
}

func plainNetwork(tcp bool) string {
	if tcp {
		return "tcp"
	}
	return "udp"
}

func exchangeClient(ctx context.Context, address, network string,
	tlsConfig *tls.Config, request *dns.Msg,
) (*dns.Msg, error) {
	client := &dns.Client{
		Net:       network,
		TLSConfig: tlsConfig,
	}
	response, _, err := client.ExchangeContext(ctx, request, address)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (e *NetExchanger) exchangeDoH(ctx context.Context, endpoint Endpoint,
	request *dns.Msg,
) (*dns.Msg, error) {
	if endpoint.URL == "" {
		return nil, fmt.Errorf("DoH endpoint %s has no URL", endpoint.Address)
	}

	client, err := e.dohClient(endpoint)
	if err != nil {
		return nil, err
	}

	wire, err := request.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("building DoH request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	httpRequest.Header.Set("Accept", "application/dns-message")

	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("performing DoH request: %w", err)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status: %s", httpResponse.Status)
	}

	body, err := io.ReadAll(io.LimitReader(httpResponse.Body,
		maxDoHResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading DoH response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking DoH response: %w", err)
	}
	return response, nil
}

func (e *NetExchanger) dohClient(endpoint Endpoint) (*http.Client, error) {
	key := endpoint.URL + "|" + endpoint.Address

	e.mutex.Lock()
	defer e.mutex.Unlock()
	if client, ok := e.dohClients[key]; ok {
		return client, nil
	}

	parsedURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing DoH URL: %w", err)
	}
	if parsedURL.Host == "" {
		return nil, errors.New("DoH URL has no host")
	}

	address, err := addressWithPort(endpoint.Address, defaultDoHPort)
	if err != nil {
		return nil, fmt.Errorf("DoH endpoint address: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert
	dialer := &net.Dialer{Timeout: e.timeout}
	transport.DialContext = func(ctx context.Context, _, _ string) (
		net.Conn, error,
	) {
		return dialer.DialContext(ctx, "tcp", address)
	}

	client := &http.Client{
		Timeout:   e.timeout,
		Transport: transport,
	}
	e.dohClients[key] = client
	return client, nil
}

func addressWithPort(address, defaultPort string) (string, error) {
	if address == "" {
		return "", errors.New("address is empty")
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err == nil {
		return addrPort.String(), nil
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", address, err)
	}
	return netip.AddrPortFrom(addr, mustPort(defaultPort)).String(), nil
}

func mustPort(port string) uint16 {
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		panic("invalid port " + port)
	}
	return uint16(value)
}
