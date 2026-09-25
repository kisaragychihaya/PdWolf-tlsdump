// Package mitm sniffs the first bytes of a client connection, decides
// whether to decrypt (whitelist hit) or blindly forward (bypass), and
// records decrypted HTTP traffic.
package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"tlsdump/internal/certmgr"
	"tlsdump/internal/filter"
	"tlsdump/internal/record"
)

const (
	establishedLine          = "HTTP/1.1 200 Connection Established\r\n\r\n"
	sniffTimeout             = 30 * time.Second
	tlsHandshakeTimeout      = 30 * time.Second
	upstreamHandshakeTimeout = 15 * time.Second
)

// errNotTLS marks a record header that is not a TLS handshake record.
var errNotTLS = errors.New("not a TLS handshake record")

// Handler classifies and processes one client connection.
type Handler struct {
	CertMgr            *certmgr.Manager
	Filter             *filter.Filter
	Log                *record.Logger
	BodyLimit          int64
	DialTimeout        time.Duration
	InsecureSkipVerify bool
	// Dialer optionally overrides outbound dialing (tun mode binds it to a
	// physical interface). Nil means use a default dialer.
	Dialer *net.Dialer
}

// BufferedConn keeps bytes already read from the underlying connection
// reachable by subsequent reads, so sniffing never loses data. It is exported
// so front-ends (proxy) can hand over a connection whose initial bytes they
// already consumed.
type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

// NewBufferedConn wraps conn with a fresh 64KB read buffer.
func NewBufferedConn(conn net.Conn) *BufferedConn {
	return &BufferedConn{Conn: conn, Reader: bufio.NewReaderSize(conn, 64*1024)}
}

// WrapBufferedConn wraps conn using r as the read buffer.
func WrapBufferedConn(conn net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: conn, Reader: r}
}

func (c *BufferedConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

// CloseWrite half-closes the underlying connection when supported.
func (c *BufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// bufferedConn is the internal alias used throughout this package.
type bufferedConn = BufferedConn

// HandleConn takes over a TCP stream bound for dstAddr. When writeEstablished
// is true (proxy CONNECT) it first replies with a 200, then sniffs.
func (h *Handler) HandleConn(ctx context.Context, conn net.Conn, dstAddr string, writeEstablished bool) {
	clientAddr := conn.RemoteAddr().String()
	slog.Debug("conn open", "client", clientAddr, "dst", dstAddr)
	defer func() {
		conn.Close()
		slog.Debug("conn closed", "client", clientAddr, "dst", dstAddr)
	}()

	bc := NewBufferedConn(conn)
	if writeEstablished {
		if _, err := io.WriteString(bc, establishedLine); err != nil {
			return
		}
	}

	_ = bc.SetReadDeadline(time.Now().Add(sniffTimeout))
	head, err := bc.Reader.Peek(5)
	if err != nil && len(head) == 0 {
		slog.Debug("sniff: no bytes", "client", clientAddr, "err", err)
		return
	}
	_ = bc.SetReadDeadline(time.Time{})

	switch {
	case looksLikeTLS(head):
		sni, sniErr := peekClientHello(bc.Reader)
		if sniErr != nil {
			slog.Debug("client hello parse failed, using fallback host", "err", sniErr, "dst", dstAddr)
		}
		host := sni
		if host == "" {
			host = dstHost(dstAddr)
		}
		if !h.Filter.Match(host) {
			slog.Debug("bypass TLS", "sni", sni, "host", host, "dst", dstAddr)
			h.bypass(ctx, bc, dstAddr, nil)
			return
		}
		slog.Debug("intercept TLS", "sni", sni, "dst", dstAddr)
		h.handleTLS(ctx, bc, dstAddr, sni, clientAddr)
	case looksLikeHTTP(head):
		slog.Debug("plaintext HTTP detected", "dst", dstAddr)
		h.handlePlainHTTP(ctx, bc, dstAddr, clientAddr)
	default:
		slog.Debug("bypass unknown traffic", "dst", dstAddr, "head", head)
		h.bypass(ctx, bc, dstAddr, nil)
	}
}

// handleTLS terminates TLS on bc and proxies HTTP inside it.
func (h *Handler) handleTLS(ctx context.Context, bc *bufferedConn, dstAddr, sni, clientAddr string) {
	fallback := dstHost(dstAddr)
	cfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				// IP-literal connects carry no SNI; fall back to the
				// destination host.
				name = fallback
			}
			return h.CertMgr.CertificateFor(name)
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	tlsConn := tls.Server(bc, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("TLS handshake failed", "sni", sni, "err", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h.serveH2(ctx, tlsConn, dstAddr, sni, fallback, clientAddr)
		return
	}
	upServerName := sni
	if upServerName == "" {
		upServerName = fallback
	}
	upstream, err := h.dialTLS(ctx, dstAddr, upServerName, []string{"http/1.1"})
	if err != nil {
		slog.Debug("dial TLS upstream failed", "dst", dstAddr, "sni", sni, "err", err)
		return
	}
	h.serveHTTP1(ctx, tlsConn, bufio.NewReaderSize(tlsConn, 64*1024), upstream, fallback, "mitm", clientAddr, nil)
}

// serveH2 runs an HTTP/2 server over the terminated TLS connection and
// forwards each request upstream over HTTP/2.
func (h *Handler) serveH2(ctx context.Context, conn *tls.Conn, dstAddr, sni, host, clientAddr string) {
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			serverName := sni
			if serverName == "" {
				serverName = host
			}
			return h.dialTLS(ctx, addr, serverName, []string{"h2"})
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h.handleH2Request(ctx, w, req, transport, host, clientAddr)
	})
	var srv http2.Server
	srv.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: handler})
}

func (h *Handler) handleH2Request(ctx context.Context, w http.ResponseWriter, req *http.Request, transport *http2.Transport, sni, clientAddr string) {
	host := req.Host
	if host == "" {
		host = sni
	}

	var reqRaw []byte
	var reqTrunc bool
	if req.Body != nil {
		reqRaw, reqTrunc, _ = record.ReadBody(req.Body, h.BodyLimit)
		_ = req.Body.Close()
	}

	outReq := req.Clone(ctx)
	outReq.RequestURI = ""
	outReq.URL.Scheme = "https"
	outReq.URL.Host = host
	outReq.Body = io.NopCloser(bytes.NewReader(reqRaw))
	outReq.ContentLength = int64(len(reqRaw))
	outReq.TransferEncoding = nil
	outReq.Header = req.Header.Clone()
	stripHopByHop(outReq.Header)

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		slog.Debug("h2 upstream round trip failed", "host", host, "err", err)
		http.Error(w, "tlsdump upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	lb := &limitedBuffer{limit: h.BodyLimit}
	respBody := io.TeeReader(resp.Body, lb)

	wh := w.Header()
	for k, vs := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			wh.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, copyErr := io.Copy(w, respBody)

	e := &record.Entry{
		Time:        time.Now(),
		Client:      clientAddr,
		Mode:        "mitm",
		Host:        host,
		Method:      req.Method,
		URI:         req.URL.RequestURI(),
		Status:      resp.StatusCode,
		ReqHeaders:  req.Header.Clone(),
		RespHeaders: resp.Header.Clone(),
		ReqBody:     record.EncodeBody(reqRaw),
		ReqTrunc:    reqTrunc,
		RespBody:    record.EncodeBody(lb.bytes()),
		RespTrunc:   lb.truncated(),
	}
	h.Log.Log(e)

	if copyErr != nil {
		slog.Debug("h2 response copy failed", "host", host, "err", copyErr)
	}
}

// handlePlainHTTP serves cleartext HTTP: the first request decides the match;
// on miss the request is replayed to the upstream inside the bypass tunnel.
func (h *Handler) handlePlainHTTP(ctx context.Context, bc *bufferedConn, dstAddr, clientAddr string) {
	br := bufio.NewReaderSize(bc, 64*1024)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !h.Filter.Match(req.Host) {
		slog.Debug("bypass HTTP", "host", req.Host, "dst", dstAddr)
		h.bypass(ctx, bc, dstAddr, req)
		return
	}
	upAddr := ensurePort(dstAddr, "80")
	if _, _, err := net.SplitHostPort(req.Host); err == nil {
		upAddr = req.Host
	}
	upstream, err := h.dial(ctx, "tcp", upAddr)
	if err != nil {
		slog.Debug("dial HTTP upstream failed", "addr", upAddr, "err", err)
		return
	}
	slog.Debug("intercept HTTP", "host", req.Host)
	h.serveHTTP1(ctx, bc, br, upstream, req.Host, "http", clientAddr, req)
}

// serveHTTP1 relays HTTP/1.x requests over an established upstream connection
// until EOF or Connection: close. clientW receives responses; clientR holds
// any bytes already buffered from the client. firstReq, when non-nil, is the
// request already consumed by the caller (used on the first loop iteration).
func (h *Handler) serveHTTP1(ctx context.Context, clientW net.Conn, clientR *bufio.Reader, upstream net.Conn, host, mode, clientAddr string, firstReq *http.Request) {
	defer upstream.Close()
	upBr := bufio.NewReader(upstream)
	var pending *http.Request = firstReq
	for {
		var req *http.Request
		if pending != nil {
			req, pending = pending, nil
		} else {
			var err error
			req, err = http.ReadRequest(clientR)
			if err != nil {
				return
			}
		}
		var reqRaw []byte
		var reqTrunc bool
		if req.Body != nil {
			reqRaw, reqTrunc, _ = record.ReadBody(req.Body, h.BodyLimit)
			_ = req.Body.Close()
		}
		reqHdr := req.Header.Clone()

		outReq := req
		outReq.Body = io.NopCloser(bytes.NewReader(reqRaw))
		outReq.ContentLength = int64(len(reqRaw))
		outReq.TransferEncoding = nil
		stripHopByHop(outReq.Header)
		if _, ok := req.Header["User-Agent"]; !ok {
			// Request.Write injects a default User-Agent; suppress it so the
			// forwarded request matches what the client actually sent.
			outReq.Header["User-Agent"] = nil
		}
		if err := outReq.Write(upstream); err != nil {
			return
		}

		resp, err := http.ReadResponse(upBr, req)
		if err != nil {
			slog.Debug("read upstream response failed", "host", host, "err", err)
			return
		}

		lb := &limitedBuffer{limit: h.BodyLimit}
		resp.Body = io.NopCloser(io.TeeReader(resp.Body, lb))
		writeErr := resp.Write(clientW)
		resp.Body.Close()

		e := &record.Entry{
			Time:        time.Now(),
			Client:      clientAddr,
			Mode:        mode,
			Host:        host,
			Method:      req.Method,
			URI:         req.URL.RequestURI(),
			Status:      resp.StatusCode,
			ReqHeaders:  reqHdr,
			RespHeaders: resp.Header.Clone(),
			ReqBody:     record.EncodeBody(reqRaw),
			ReqTrunc:    reqTrunc,
			RespBody:    record.EncodeBody(lb.bytes()),
			RespTrunc:   lb.truncated(),
		}
		h.Log.Log(e)

		if writeErr != nil || req.Close || resp.Close {
			return
		}
	}
}

// bypass blindly relays between conn and the upstream, optionally replaying
// one already-parsed request (filter miss on the first request). Bytes
// already buffered in conn are forwarded first.
func (h *Handler) bypass(ctx context.Context, conn *bufferedConn, dstAddr string, replay *http.Request) {
	upstream, err := h.dial(ctx, "tcp", dstAddr)
	if err != nil {
		slog.Debug("bypass dial failed", "dst", dstAddr, "err", err)
		return
	}
	defer upstream.Close()
	if replay != nil {
		// The request body, if any, is still unread in conn's buffer;
		// Write pulls it from there before the copies below take over.
		replay.RequestURI = ""
		stripHopByHop(replay.Header)
		if _, ok := replay.Header["User-Agent"]; !ok {
			replay.Header["User-Agent"] = nil
		}
		if err := replay.Write(upstream); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, conn)
		_ = closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, upstream)
		_ = closeWrite(conn)
	}()
	wg.Wait()
}

// closeWrite half-closes c when the transport supports it.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// dial dials addr using the configured Dialer or a default.
func (h *Handler) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if h.Dialer != nil {
		return h.Dialer.DialContext(ctx, network, addr)
	}
	d := &net.Dialer{Timeout: h.DialTimeout}
	return d.DialContext(ctx, network, addr)
}

// dialTLS dials addr and wraps the connection in a client TLS handshake with
// the given SNI and ALPN protocols.
func (h *Handler) dialTLS(ctx context.Context, addr, serverName string, alpn []string) (net.Conn, error) {
	raw, err := h.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: h.InsecureSkipVerify, //nolint:gosec // explicit option for self-signed upstreams
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(upstreamHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Proxy-Connection",
}

func isHopByHop(k string) bool {
	for _, hop := range hopByHopHeaders {
		if strings.EqualFold(k, hop) {
			return true
		}
	}
	return false
}

// stripHopByHop removes hop-by-hop headers, including those named by the
// Connection header.
func stripHopByHop(h http.Header) {
	for _, f := range strings.Split(h.Get("Connection"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			h.Del(f)
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

var httpMethodPrefixes = []string{
	"GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
	"OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
}

func looksLikeHTTP(head []byte) bool {
	for _, m := range httpMethodPrefixes {
		if len(head) >= len(m) && string(head[:len(m)]) == m {
			return true
		}
	}
	return false
}

func looksLikeTLS(head []byte) bool {
	return len(head) >= 2 && head[0] == 0x16 && head[1] == 0x03
}

// dstHost extracts the host part of a host:port address for fallback
// filtering when a client hello carries no SNI.
func dstHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(addr, "[]")
}

// ensurePort appends defaultPort when addr has no port.
func ensurePort(addr, defaultPort string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Count(addr, ":") > 1 {
		return "[" + strings.Trim(addr, "[]") + "]:" + defaultPort
	}
	return addr + ":" + defaultPort
}

// peekClientHello parses the TLS record and ClientHello handshake without
// consuming bytes from br, returning the SNI server_name (empty if absent).
func peekClientHello(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != 0x16 || hdr[1] != 0x03 {
		return "", errNotTLS
	}
	recordLen := int(hdr[3])<<8 | int(hdr[4])
	if recordLen > 64*1024 {
		return "", errors.New("TLS record too large")
	}
	rec, err := br.Peek(5 + recordLen)
	if err != nil {
		return "", err
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 0x01 { // client_hello
		return "", errors.New("no client hello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen+4 > len(hs) {
		return "", errors.New("fragmented client hello")
	}
	return parseClientHelloExtensions(hs[4 : 4+hsLen]), nil
}

// parseClientHelloExtensions walks a ClientHello body and returns the first
// server_name, or "" if none is present.
func parseClientHelloExtensions(body []byte) string {
	pos := 2 + 32 // version + random
	if pos+1 > len(body) {
		return ""
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return ""
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2 + csLen
	if pos+1 > len(body) {
		return ""
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return ""
	}
	extTotal := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	end := min(pos+extTotal, len(body))
	for pos+4 <= end {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extLen > end {
			return ""
		}
		if extType == 0 { // server_name
			return parseServerNameExt(body[pos : pos+extLen])
		}
		pos += extLen
	}
	return ""
}

func parseServerNameExt(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos, end := 2, min(2+listLen, len(data))
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3
		if pos+nameLen > end {
			return ""
		}
		if nameType == 0 { // host_name
			return string(data[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

// limitedBuffer captures the first limit bytes written to it.
type limitedBuffer struct {
	limit int64
	buf   []byte
	over  bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - int64(len(b.buf))
	if int64(len(p)) > room {
		b.over = true
	}
	if room > 0 {
		take := p
		if int64(len(take)) > room {
			take = take[:room]
		}
		b.buf = append(b.buf, take...)
	}
	return len(p), nil
}

func (b *limitedBuffer) bytes() []byte   { return b.buf }
func (b *limitedBuffer) truncated() bool { return b.over }
