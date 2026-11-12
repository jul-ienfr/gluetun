//go:build !linux

package main

import "errors"

func runWireGuard([]string) error {
	return errors.New("the WireGuard harness requires Linux")
}

func checkWireGuardTunnel(checkSettings) error {
	return errors.New("the WireGuard tunnel check requires Linux")
}
