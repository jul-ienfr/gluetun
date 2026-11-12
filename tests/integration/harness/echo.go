package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const echoReadHeaderTimeout = 5 * time.Second

type echoSettings struct {
	listen  string
	name    string
	ip      string
	status  int
	fail    bool
	body    string
	headers bool
}

func parseEchoSettings(args []string) (settings echoSettings, err error) {
	flags := flag.NewFlagSet("echo", flag.ContinueOnError)
	flags.StringVar(&settings.listen, "listen", "0.0.0.0:8080",
		"listen address")
	flags.StringVar(&settings.name, "name", "", "source name, defaults to the hostname")
	flags.StringVar(&settings.ip, "ip", "auto",
		"reported IPv4 address, auto uses the request remote address")
	flags.IntVar(&settings.status, "status", http.StatusServiceUnavailable,
		"status returned by /ip and /canary when -fail is set")
	flags.BoolVar(&settings.fail, "fail", false,
		"make /ip and /canary fail with -status")
	flags.StringVar(&settings.body, "body", "ok", "body returned by /canary")
	flags.BoolVar(&settings.headers, "headers", false,
		"include request headers in /ip responses")

	err = flags.Parse(args)
	if err != nil {
		return settings, err
	}

	if settings.name == "" {
		settings.name, _ = os.Hostname()
	}
	if settings.ip != "auto" {
		ip := net.ParseIP(settings.ip)
		if ip == nil || ip.To4() == nil {
			return settings, fmt.Errorf("invalid IPv4 address %q", settings.ip)
		}
	}

	return settings, nil
}

func runEcho(args []string) (err error) {
	settings, err := parseEchoSettings(args)
	if err != nil {
		return err
	}

	handler := newEchoHandler(settings)
	server := &http.Server{
		Addr:              settings.listen,
		Handler:           handler,
		ReadHeaderTimeout: echoReadHeaderTimeout,
	}

	errorsChannel := make(chan error, 1)
	go func() {
		errorsChannel <- server.ListenAndServe()
	}()
	fmt.Printf("echo: %s listening on %s reporting %s\n",
		settings.name, settings.listen, settings.ip)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signalChannel:
		fmt.Printf("echo: received %s, shutting down\n", sig)
		_ = server.Close()
		return nil
	case err := <-errorsChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serving HTTP: %w", err)
	}
}

func newEchoHandler(settings echoSettings) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/ip", func(writer http.ResponseWriter, request *http.Request) {
		if settings.fail {
			http.Error(writer, "injected failure", settings.status)
			return
		}
		writeJSON(writer, http.StatusOK, echoResponse(settings, request))
	})

	mux.HandleFunc("/canary", func(writer http.ResponseWriter, _ *http.Request) {
		if settings.fail {
			http.Error(writer, "injected failure", settings.status)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(settings.body + "\n")) //nolint:gosec // harness-controlled body
	})

	mux.HandleFunc("/status/", func(writer http.ResponseWriter, request *http.Request) {
		raw := strings.TrimPrefix(request.URL.Path, "/status/")
		status, err := strconv.Atoi(raw)
		if err != nil || status < 100 || status > 599 {
			http.Error(writer, "invalid status", http.StatusBadRequest)
			return
		}
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(http.StatusText(status) + "\n"))
	})

	mux.HandleFunc("/delay/", func(writer http.ResponseWriter, request *http.Request) {
		raw := strings.TrimPrefix(request.URL.Path, "/delay/")
		milliseconds, err := strconv.Atoi(raw)
		if err != nil || milliseconds < 0 || milliseconds > 60000 {
			http.Error(writer, "invalid delay", http.StatusBadRequest)
			return
		}
		time.Sleep(time.Duration(milliseconds) * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, echoResponse(settings, request))
	})

	return mux
}

type echoResponseBody struct {
	Source  string            `json:"source"`
	IP      string            `json:"ip"`
	Remote  string            `json:"remote"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

func echoResponse(settings echoSettings, request *http.Request) echoResponseBody {
	ip := settings.ip
	if ip == "auto" {
		ip = remoteIP(request)
	}

	response := echoResponseBody{
		Source: settings.name,
		IP:     ip,
		Remote: remoteIP(request),
		Method: request.Method,
		Path:   request.URL.RequestURI(),
	}

	if settings.headers {
		response.Headers = make(map[string]string, len(request.Header))
		for key := range request.Header {
			response.Headers[key] = request.Header.Get(key)
		}
	}

	return response
}

func remoteIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return
	}
}
