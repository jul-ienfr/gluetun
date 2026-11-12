package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultTTL          = 60
	maxServers          = 2
	certificateValidity = 24 * time.Hour
	certificateBackdate = time.Hour
	caSerialNumber      = 1
	leafSerialNumber    = 2
)

type dnsSettings struct {
	mode     string
	listen   string
	answer   string
	answer6  string
	dotName  string
	caOut    string
	certOut  string
	keyOut   string
	ttl      uint32
	failAll  bool
	nxdomain bool
	delay    time.Duration
}

func parseDNSSettings(args []string) (settings dnsSettings, err error) {
	flags := flag.NewFlagSet("dns", flag.ContinueOnError)
	flags.StringVar(&settings.mode, "mode", "plain",
		"server mode: plain or dot")
	flags.StringVar(&settings.listen, "listen", "",
		"listen address, defaults to :53 for plain and :853 for dot")
	flags.StringVar(&settings.answer, "answer", "198.51.100.53",
		"IPv4 address answered for A queries")
	flags.StringVar(&settings.answer6, "answer6", "",
		"IPv6 address answered for AAAA queries, empty means NODATA")
	flags.StringVar(&settings.dotName, "dot-name", "dot.test",
		"TLS server name for the DoT certificate")
	flags.StringVar(&settings.caOut, "ca-out", "",
		"path to write the generated CA certificate")
	flags.StringVar(&settings.certOut, "cert-out", "",
		"path to write the generated DoT certificate")
	flags.StringVar(&settings.keyOut, "key-out", "",
		"path to write the generated DoT private key")
	ttl := flags.Uint64("ttl", defaultTTL, "answer TTL in seconds")
	flags.BoolVar(&settings.failAll, "fail", false,
		"answer SERVFAIL for every query")
	flags.BoolVar(&settings.nxdomain, "nxdomain", false,
		"answer NXDOMAIN for names other than verify.test")
	flags.DurationVar(&settings.delay, "delay", 0,
		"delay before answering each query")

	err = flags.Parse(args)
	if err != nil {
		return settings, err
	}
	if *ttl > math.MaxUint32 {
		return settings, fmt.Errorf("TTL %d is too large", *ttl)
	}
	settings.ttl = uint32(*ttl)

	switch settings.mode {
	case "plain":
		if settings.listen == "" {
			settings.listen = "0.0.0.0:53"
		}
	case "dot":
		if settings.listen == "" {
			settings.listen = "0.0.0.0:853"
		}
	default:
		return settings, fmt.Errorf("mode must be plain or dot, got %q",
			settings.mode)
	}

	if settings.answer != "" {
		ip := net.ParseIP(settings.answer)
		if ip == nil || ip.To4() == nil {
			return settings, fmt.Errorf("invalid IPv4 answer %q", settings.answer)
		}
	}
	if settings.answer6 != "" && net.ParseIP(settings.answer6) == nil {
		return settings, fmt.Errorf("invalid IPv6 answer %q", settings.answer6)
	}

	return settings, nil
}

func runDNS(args []string) (err error) {
	settings, err := parseDNSSettings(args)
	if err != nil {
		return err
	}

	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		if settings.delay > 0 {
			time.Sleep(settings.delay)
		}
		response := answerQuery(request, settings)
		_ = writer.WriteMsg(response)
	})

	servers := make([]*dns.Server, 0, maxServers)
	switch settings.mode {
	case "plain":
		servers = append(servers,
			&dns.Server{Addr: settings.listen, Net: "udp", Handler: handler},
			&dns.Server{Addr: settings.listen, Net: "tcp", Handler: handler},
		)
	case "dot":
		certificate, err := loadOrCreateCertificate(settings)
		if err != nil {
			return err
		}
		servers = append(servers, &dns.Server{
			Addr:    settings.listen,
			Net:     "tcp-tls",
			Handler: handler,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{certificate},
				ServerName:   settings.dotName,
			},
		})
	}

	errorsChannel := make(chan error, len(servers))
	for _, server := range servers {
		fmt.Printf("dns: %s listening on %s (%s)\n",
			settings.mode, settings.listen, server.Net)
		go func() {
			errorsChannel <- server.ListenAndServe()
		}()
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signalChannel:
		fmt.Printf("dns: received %s, shutting down\n", sig)
		for _, server := range servers {
			_ = server.Shutdown()
		}
		return nil
	case err := <-errorsChannel:
		if err == nil {
			return nil
		}
		return fmt.Errorf("serving DNS: %w", err)
	}
}

func answerQuery(request *dns.Msg, settings dnsSettings) (response *dns.Msg) {
	response = new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true

	if len(request.Question) != 1 {
		response.Rcode = dns.RcodeFormatError
		return response
	}

	question := request.Question[0]
	name := strings.ToLower(question.Name)

	switch {
	case settings.failAll || name == "servfail.test.":
		response.Rcode = dns.RcodeServerFailure
		return response
	case name == "refused.test.":
		response.Rcode = dns.RcodeRefused
		return response
	case settings.nxdomain && name != "verify.test.":
		response.Rcode = dns.RcodeNameError
		return response
	}

	switch question.Qtype {
	case dns.TypeA:
		if settings.answer == "" {
			return response
		}
		record, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s",
			question.Name, settings.ttl, settings.answer))
		if err == nil {
			response.Answer = append(response.Answer, record)
		}
	case dns.TypeAAAA:
		if settings.answer6 == "" {
			return response
		}
		record, err := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s",
			question.Name, settings.ttl, settings.answer6))
		if err == nil {
			response.Answer = append(response.Answer, record)
		}
	}

	return response
}

func loadOrCreateCertificate(settings dnsSettings) (certificate tls.Certificate,
	err error,
) {
	if settings.certOut != "" && settings.keyOut != "" {
		if fileExists(settings.certOut) && fileExists(settings.keyOut) {
			return tls.LoadX509KeyPair(settings.certOut, settings.keyOut)
		}
	}

	caCertificate, caKey, err := generateCA()
	if err != nil {
		return certificate, err
	}
	leafCertificate, leafKey, err := generateLeaf(caCertificate, caKey,
		settings.dotName)
	if err != nil {
		return certificate, err
	}

	if settings.caOut != "" {
		err = writePEM(settings.caOut, "CERTIFICATE", caCertificate.Raw)
		if err != nil {
			return certificate, err
		}
	}

	certificate = tls.Certificate{
		Certificate: [][]byte{leafCertificate.Raw},
		PrivateKey:  leafKey,
	}

	if settings.certOut != "" {
		err = writePEM(settings.certOut, "CERTIFICATE", leafCertificate.Raw)
		if err != nil {
			return certificate, err
		}
	}

	if settings.keyOut != "" {
		der, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			return certificate, fmt.Errorf("marshaling private key: %w", err)
		}
		err = writePEM(settings.keyOut, "EC PRIVATE KEY", der)
		if err != nil {
			return certificate, err
		}
	}

	return certificate, nil
}

func generateCA() (certificate *x509.Certificate, key *ecdsa.PrivateKey,
	err error,
) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(caSerialNumber),
		Subject:               pkix.Name{CommonName: "gluetun harness CA"},
		NotBefore:             time.Now().Add(-certificateBackdate),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template,
		&key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	return certificate, key, nil
}

func generateLeaf(caCertificate *x509.Certificate, caKey *ecdsa.PrivateKey,
	serverName string,
) (certificate *x509.Certificate, key *ecdsa.PrivateKey, err error,
) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating leaf key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(leafSerialNumber),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-certificateBackdate),
		NotAfter:     time.Now().Add(certificateValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName, "localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCertificate,
		&key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating leaf certificate: %w", err)
	}

	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	return certificate, key, nil
}

func writePEM(path, blockType string, der []byte) (err error) {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("closing %s: %w", path, closeErr)
		}
	}()

	err = pem.Encode(file, &pem.Block{Type: blockType, Bytes: der})
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
