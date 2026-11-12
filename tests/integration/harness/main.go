// Command harness provides deterministic local services for Gluetun control
// plane integration tests: plain DNS, DNS over TLS, HTTP egress echoes and a
// WireGuard test endpoint. It is only used by tests/integration.
package main

import (
	"fmt"
	"os"
)

const (
	minArguments  = 2
	usageExitCode = 2
)

func main() {
	if len(os.Args) < minArguments {
		usage()
		os.Exit(usageExitCode)
	}

	var err error
	switch os.Args[1] {
	case "dns":
		err = runDNS(os.Args[2:])
	case "echo":
		err = runEcho(os.Args[2:])
	case "wg":
		err = runWireGuard(os.Args[2:])
	case "check":
		err = runCheck(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: harness <command> [flags]

commands:
  dns    serve plain DNS or DNS over TLS
  echo   serve HTTP egress echo endpoints
  wg     serve a WireGuard test endpoint (Linux)
  check  verify the harness services are working
`)
}
