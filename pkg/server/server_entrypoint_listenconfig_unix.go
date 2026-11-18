//go:build linux || freebsd || openbsd || darwin

package server

import (
	"fmt"
	"net"
	"syscall"

	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/fingerprint"
	"golang.org/x/sys/unix"
)

// newListenConfig creates a new net.ListenConfig for the given configuration of
// the entry point.
func newListenConfig(configuration *static.EntryPoint) (lc net.ListenConfig) {
	if configuration == nil {
		return
	}
	wantReuse := configuration.ReusePort
	wantSYN := configuration.Fingerprint.TCPSYNEnabled()
	switch {
	case wantReuse && wantSYN:
		lc.Control = func(network, address string, c syscall.RawConn) error {
			if err := controlReusePort(network, address, c); err != nil {
				return err
			}
			return fingerprint.ControlTCPSaveSYN(network, address, c)
		}
	case wantReuse:
		lc.Control = controlReusePort
	case wantSYN:
		lc.Control = fingerprint.ControlTCPSaveSYN
	}
	return
}

// controlReusePort is a net.ListenConfig.Control function that enables SO_REUSEPORT
// on the socket.
func controlReusePort(network, address string, c syscall.RawConn) error {
	var setSockOptErr error
	err := c.Control(func(fd uintptr) {
		// Note that net.ListenConfig enables unix.SO_REUSEADDR by default,
		// as seen in https://go.dev/src/net/sockopt_linux.go. Therefore, no
		// additional action is required to enable it here.

		setSockOptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unixSOREUSEPORT, 1)
		if setSockOptErr != nil {
			return
		}
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if setSockOptErr != nil {
		return fmt.Errorf("setsockopt: %w", setSockOptErr)
	}
	return nil
}
