//go:build !darwin && !linux

package netcfg

import (
	"fmt"
	"net/netip"
	"runtime"
)

func ConfigureTun(TunSetup) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: tun setup not supported on %s", runtime.GOOS)
}

func captureDefault(string, netip.Addr) (*chain, error) {
	return nil, fmt.Errorf("netcfg: default-route capture not supported on %s", runtime.GOOS)
}

func PinRoutes([]PinRoute) (TeardownFunc, error) {
	return func() error { return nil }, nil
}

func PinIfaceDefault(IfaceRoute) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: PinIfaceDefault not supported on %s", runtime.GOOS)
}

func ConfigureLANForward(LANForward) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: ConfigureLANForward not supported on %s", runtime.GOOS)
}

func DefaultGatewayVia(string) (string, error) {
	return "", fmt.Errorf("netcfg: DefaultGatewayVia not supported on %s", runtime.GOOS)
}

func ConfigureNAT(NATSetup) (TeardownFunc, error) {
	return nil, fmt.Errorf("netcfg: NAT not supported on %s", runtime.GOOS)
}
