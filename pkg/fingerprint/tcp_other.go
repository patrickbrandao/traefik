//go:build !linux

package fingerprint

import (
	"net"
	"syscall"
)

// ControlTCPSaveSYN is a no-op on non-Linux platforms where TCP_SAVE_SYN is unavailable.
func ControlTCPSaveSYN(_, _ string, _ syscall.RawConn) error {
	return nil
}

// CaptureAcceptedTCP is a silent fallback on non-Linux platforms.
func CaptureAcceptedTCP(_ *net.TCPConn, _ *ConnData) {}

// CaptureTCPInfoRTT is a silent fallback on non-Linux platforms.
func CaptureTCPInfoRTT(_ *net.TCPConn, _ *ConnData) {}

// ReadPacketUDPWithOOB falls back to a standard UDP ReadFrom on non-Linux platforms.
func ReadPacketUDPWithOOB(udpConn *net.UDPConn, p []byte) (n int, addr net.Addr, ttl, ecn uint8, err error) {
	n, addr, err = udpConn.ReadFrom(p)
	return n, addr, 0, 0, err
}
