// Package proxy implements the local HTTP/CONNECT proxy front-end.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"tlsdump/internal/mitm"
)

const requestTimeout = 30 * time.Second

// Server is a plain HTTP proxy that hands every connection to the mitm
// Handler for sniffing and processing.
type Server struct {
	Addr string
	H    *mitm.Handler
}

// ListenAndServe accepts connections until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	slog.Info("proxy listening", "addr", ln.Addr().String())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
	br := bufio.NewReaderSize(conn, 64*1024)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	bc := mitm.WrapBufferedConn(conn, br)
	if req.Method == http.MethodConnect {
		slog.Debug("CONNECT", "client", conn.RemoteAddr().String(), "host", req.Host)
		s.H.HandleConn(ctx, bc, req.Host, true)
		return
	}
	if req.URL == nil || req.Host == "" {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	// Replay the consumed request so HandleConn sees a faithful stream.
	var buf bytes.Buffer
	if err := req.WriteProxy(&buf); err != nil {
		return
	}
	s.H.HandleConn(ctx, &prefixConn{Conn: bc, prefix: buf.Bytes()}, req.Host, false)
}

// prefixConn yields prefix bytes before reading from the underlying
// connection, so bytes already consumed by the proxy are not lost.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
