// SOCKS5 (RFC 1928) front-end support: no-auth method negotiation and the
// CONNECT command only. UDP ASSOCIATE and BIND are rejected.
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"time"

	"tlsdump/internal/mitm"
)

const (
	socks5Version = 0x05

	socks5AuthNone       = 0x00
	socks5AuthNoAccepted = 0xFF

	socks5CmdConnect = 0x01

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5RepSuccess              = 0x00
	socks5RepCmdNotSupported      = 0x07
	socks5RepAddrTypeNotSupported = 0x08
)

// handleSocks5 runs the SOCKS5 handshake on an accepted connection and hands
// the established stream to the mitm handler. The SOCKS5 success reply stands
// in for HandleConn's writeEstablished response, so it is passed false.
func (s *Server) handleSocks5(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	dst, ok := socks5Handshake(conn, br)
	if !ok {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	slog.Debug("SOCKS5 CONNECT", "client", conn.RemoteAddr().String(), "host", dst)
	s.H.HandleConn(ctx, mitm.WrapBufferedConn(conn, br), dst, false)
}

// socks5Handshake negotiates no-auth, reads the CONNECT request and replies
// success, returning the target as host:port. On any failure it replies with
// the appropriate error code (when the client can still read it) and returns
// ok=false; the caller then just closes the connection.
func socks5Handshake(conn net.Conn, br *bufio.Reader) (dst string, ok bool) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != socks5Version {
		return "", false
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return "", false
	}
	method := byte(socks5AuthNoAccepted)
	if slices.Contains(methods, socks5AuthNone) {
		method = socks5AuthNone
	}
	if _, err := conn.Write([]byte{socks5Version, method}); err != nil || method == socks5AuthNoAccepted {
		return "", false
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != socks5Version {
		return "", false
	}
	if req[1] != socks5CmdConnect {
		slog.Debug("SOCKS5 unsupported command", "cmd", req[1])
		_ = socks5Reply(conn, socks5RepCmdNotSupported)
		return "", false
	}
	host, err := socks5ReadAddr(br, req[3])
	if err != nil {
		slog.Debug("SOCKS5 bad address", "atyp", req[3], "err", err)
		_ = socks5Reply(conn, socks5RepAddrTypeNotSupported)
		return "", false
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return "", false
	}
	if err := socks5Reply(conn, socks5RepSuccess); err != nil {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf[:])))), true
}

// socks5ReadAddr reads one address of the given type from br.
func socks5ReadAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socks5AtypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socks5AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", strconv.ErrSyntax
	}
}

// socks5Reply writes a reply with the given code and a zero BND.ADDR/BND.PORT;
// CONNECT clients do not use the bound address.
func socks5Reply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
