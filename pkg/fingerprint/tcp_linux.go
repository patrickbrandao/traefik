//go:build linux

package fingerprint

import (
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ControlTCPSaveSYN enables TCP_SAVE_SYN on TCP listeners and IP TTL/TOS control messages on UDP sockets.
// Unsupported socket options on restricted kernels are ignored so listener startup never fails.
func ControlTCPSaveSYN(network, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		sockFD := int(fd)
		switch {
		case strings.HasPrefix(network, "tcp"):
			_ = unix.SetsockoptInt(sockFD, unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
		case strings.HasPrefix(network, "udp"):
			_ = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
			_ = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
			if network == "udp" || network == "udp6" {
				_ = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
				_ = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
			}
		}
	})
	return nil
}

// CaptureAcceptedTCP reads TCP_SAVED_SYN and initial TCP_INFO RTT immediately after Accept on Linux.
func CaptureAcceptedTCP(tcpConn *net.TCPConn, out *ConnData) {
	if tcpConn == nil || out == nil {
		return
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		sockFD := int(fd)
		if rawSYN, synErr := getsockoptSavedSYN(sockFD); synErr == nil && len(rawSYN) > 0 {
			ParseRawSYN(rawSYN, out)
			// Release the saved SYN buffer inside the kernel once parsed.
			_ = unix.SetsockoptInt(sockFD, unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 0)
		}
		if info, infoErr := unix.GetsockoptTCPInfo(sockFD, unix.IPPROTO_TCP, unix.TCP_INFO); infoErr == nil && info != nil && info.Rtt > 0 {
			out.Lock()
			out.TCPRTT = time.Duration(info.Rtt) * time.Microsecond
			out.Unlock()
		}
	})
}

func getsockoptSavedSYN(fd int) ([]byte, error) {
	var buf [256]byte
	vallen := uint32(len(buf))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.IPPROTO_TCP),
		uintptr(unix.TCP_SAVED_SYN),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&vallen)),
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	if vallen == 0 || int(vallen) > len(buf) {
		return nil, nil
	}
	out := make([]byte, vallen)
	copy(out, buf[:vallen])
	return out, nil
}

// CaptureTCPInfoRTT refreshes the kernel TCP RTT estimate from TCP_INFO when not yet populated.
func CaptureTCPInfoRTT(tcpConn *net.TCPConn, out *ConnData) {
	if tcpConn == nil || out == nil {
		return
	}
	out.RLock()
	hasRTT := out.TCPRTT > 0
	out.RUnlock()
	if hasRTT {
		return
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		if info, infoErr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); infoErr == nil && info != nil && info.Rtt > 0 {
			out.Lock()
			if out.TCPRTT == 0 {
				out.TCPRTT = time.Duration(info.Rtt) * time.Microsecond
			}
			out.Unlock()
		}
	})
}

// ReadPacketUDPWithOOB reads a UDP datagram along with out-of-band IP TTL/HopLimit and ECN bits on Linux.
func ReadPacketUDPWithOOB(udpConn *net.UDPConn, p []byte) (n int, addr net.Addr, ttl, ecn uint8, err error) {
	var oob [128]byte
	n, oobn, _, udpAddr, err := udpConn.ReadMsgUDP(p, oob[:])
	if udpAddr != nil {
		addr = udpAddr
	}
	if err != nil || oobn <= 0 {
		return n, addr, 0, 0, err
	}

	msgs, cmsgErr := syscall.ParseSocketControlMessage(oob[:oobn])
	if cmsgErr != nil {
		return n, addr, 0, 0, err
	}
	for _, m := range msgs {
		switch m.Header.Level {
		case unix.IPPROTO_IP:
			if (m.Header.Type == unix.IP_TTL || m.Header.Type == unix.IP_RECVTTL) && len(m.Data) >= 1 {
				ttl = m.Data[0]
			}
			if (m.Header.Type == unix.IP_TOS || m.Header.Type == unix.IP_RECVTOS) && len(m.Data) >= 1 {
				ecn = m.Data[0] & 0x03
			}
		case unix.IPPROTO_IPV6:
			if (m.Header.Type == unix.IPV6_HOPLIMIT || m.Header.Type == unix.IPV6_RECVHOPLIMIT) && len(m.Data) >= 1 {
				ttl = m.Data[0]
			}
			if (m.Header.Type == unix.IPV6_TCLASS || m.Header.Type == unix.IPV6_RECVTCLASS) && len(m.Data) >= 1 {
				ecn = m.Data[0] & 0x03
			}
		}
	}
	return n, addr, ttl, ecn, nil
}
