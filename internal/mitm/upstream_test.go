package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"

	"tlsdump/internal/certmgr"
	"tlsdump/internal/filter"
	"tlsdump/internal/record"
)

const upstreamBody = "hello-upstream"

// newALPNTestServer starts a TLS upstream advertising exactly the given ALPN
// protocols. The certificate is the httptest localhost cert, so tests use
// insecureSkipVerify.
func newALPNTestServer(t *testing.T, protos []string, enableHTTP2 bool, addrs ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, upstreamBody)
	}))
	if len(addrs) > 0 {
		ln, err := net.Listen("tcp", addrs[0])
		if err != nil {
			t.Fatalf("Listen(%q): %v", addrs[0], err)
		}
		srv.Listener = ln
	}
	srv.EnableHTTP2 = enableHTTP2
	srv.TLS = &tls.Config{NextProtos: protos}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func upstreamRequest(t *testing.T, authority string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+authority+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func readUpstreamResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != upstreamBody {
		t.Fatalf("body = %q, want %q", body, upstreamBody)
	}
}

func TestUpstreamDispatcherHTTP1Only(t *testing.T) {
	srv := newALPNTestServer(t, []string{"http/1.1"}, false)
	h := &Handler{}
	h.SetRuntime(filter.Parse(nil), record.New(io.Discard, 0), 0, true)
	d := newUpstreamDispatcher(context.Background(), h, strings.TrimPrefix(srv.URL, "https://"), "example.com")

	resp, err := d.RoundTrip(upstreamRequest(t, "example.com"))
	if err != nil {
		t.Fatalf("RoundTrip over HTTP/1.1-only upstream: %v", err)
	}
	readUpstreamResponse(t, resp)
	if _, ok := d.transport.(*http.Transport); !ok {
		t.Fatalf("selected transport = %T, want *http.Transport", d.transport)
	}
}

func TestUpstreamDispatcherHTTP2(t *testing.T) {
	srv := newALPNTestServer(t, []string{"h2"}, true)
	h := &Handler{}
	h.SetRuntime(filter.Parse(nil), record.New(io.Discard, 0), 0, true)
	d := newUpstreamDispatcher(context.Background(), h, strings.TrimPrefix(srv.URL, "https://"), "example.com")

	resp, err := d.RoundTrip(upstreamRequest(t, "example.com"))
	if err != nil {
		t.Fatalf("RoundTrip over h2 upstream: %v", err)
	}
	readUpstreamResponse(t, resp)
	if resp.ProtoMajor != 2 {
		t.Fatalf("upstream response protocol = HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	if _, ok := d.transport.(*http2.Transport); !ok {
		t.Fatalf("selected transport = %T, want *http2.Transport", d.transport)
	}
}

func TestUpstreamDispatcherDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	h := &Handler{}
	h.SetRuntime(filter.Parse(nil), record.New(io.Discard, 0), 0, true)
	d := newUpstreamDispatcher(context.Background(), h, addr, "example.com")
	if _, err := d.RoundTrip(upstreamRequest(t, "example.com")); err == nil {
		t.Fatal("RoundTrip succeeded on a closed upstream, want dial/handshake error")
	}
	if _, err := d.RoundTrip(upstreamRequest(t, "example.com")); err == nil {
		t.Fatal("second RoundTrip lost the probe error")
	}
	if d.transport != nil {
		t.Fatal("failed probe still selected a transport")
	}
}

func TestH2UpstreamErrorHeader(t *testing.T) {
	replayer := &errRoundTripper{err: errors.New(`upstream ALPN failed\r\nsecond line`)}
	w := httptest.NewRecorder()
	h := &Handler{}
	h.SetRuntime(filter.Parse(nil), record.New(io.Discard, 0), 0, false)
	req := upstreamRequest(t, "example.com")
	h.handleH2Request(context.Background(), w, req, replayer, "example.com", "127.0.0.1:1")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	got := w.Header().Get("X-Tlsdump-Error")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("error header is not single-line: %q", got)
	}
	if !strings.HasPrefix(got, "upstream ALPN/h2 negotiation failed: ") {
		t.Fatalf("error header = %q, want ALPN negotiation prefix", got)
	}
	if !strings.Contains(got, "second line") {
		t.Fatalf("error header = %q, want full error summary", got)
	}
}

type errRoundTripper struct{ err error }

func (rt *errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, rt.err }

func TestUpstreamDispatcherConcurrentRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name        string
		protos      []string
		enableHTTP2 bool
	}{
		{name: "http1", protos: []string{"http/1.1"}},
		{name: "http2", protos: []string{"h2"}, enableHTTP2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newALPNTestServer(t, tc.protos, tc.enableHTTP2)
			h := &Handler{}
			h.SetRuntime(filter.Parse(nil), record.New(io.Discard, 0), 0, true)
			d := newUpstreamDispatcher(context.Background(), h, strings.TrimPrefix(srv.URL, "https://"), "example.com")

			const requests = 12
			var wg sync.WaitGroup
			errs := make(chan error, requests)
			start := make(chan struct{})
			for range requests {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					resp, err := d.RoundTrip(upstreamRequest(t, "example.com"))
					if err == nil {
						defer resp.Body.Close()
						var body []byte
						body, err = io.ReadAll(resp.Body)
						if err == nil && string(body) != upstreamBody {
							err = fmt.Errorf("body = %q, want %q", body, upstreamBody)
						}
						if err == nil && resp.StatusCode != http.StatusOK {
							err = fmt.Errorf("status = %d, want 200", resp.StatusCode)
						}
					}
					errs <- err
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("concurrent RoundTrip: %v", err)
				}
			}
			d.mu.Lock()
			used := d.probedConnUsed
			d.mu.Unlock()
			if !used {
				t.Fatal("probe connection was never handed to the transport")
			}
		})
	}
}

// TestH2ClientToHTTP1UpstreamRegression reproduces the reported bug: the
// client negotiates h2 with tlsdump while the upstream only speaks HTTP/1.1.
// Before the dispatcher, every request failed with an HTTP/2 frame parse error.
func TestH2ClientToHTTP1UpstreamRegression(t *testing.T) {
	newALPNTestServer(t, []string{"http/1.1"}, false, "127.0.0.1:443")

	certDir := t.TempDir()
	certMgr, err := certmgr.LoadOrCreate(certDir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read test CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append test CA to root pool")
	}

	recordPath := filepath.Join(t.TempDir(), "rec.jsonl")
	recordFile, err := os.Create(recordPath)
	if err != nil {
		t.Fatalf("create record file: %v", err)
	}
	defer recordFile.Close()

	// Bind the upstream to 127.0.0.1:443 so the fixed tun destination
	// "example.com:443" only needs a fake DNS answer for the hostname; the
	// dialer itself remains a real *net.Dialer.
	h := &Handler{
		CertMgr: certMgr,
		Dialer: &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					client, server := net.Pipe()
					go serveFakeDNS(server, net.ParseIP("127.0.0.1"))
					return client, nil
				},
			},
		},
	}
	h.SetRuntime(filter.Parse([]string{"example.com"}), record.New(recordFile, 4096), 4096, true)

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer front.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, err := front.Accept()
		if err != nil {
			return
		}
		h.HandleConn(ctx, conn, "example.com:443", false)
	}()

	clientCfg := &tls.Config{
		ServerName: "example.com",
		RootCAs:    roots,
		NextProtos: []string{"h2"},
	}
	client := &http.Client{Transport: &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", front.Addr().String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, clientCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}}
	defer client.CloseIdleConnections()

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read client body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; X-Tlsdump-Error = %q", resp.StatusCode, resp.Header.Get("X-Tlsdump-Error"))
	}
	if string(body) != upstreamBody {
		t.Fatalf("body = %q, want %q", body, upstreamBody)
	}
	if got := resp.Header.Get("X-Tlsdump-Error"); got != "" {
		t.Fatalf("unexpected X-Tlsdump-Error: %q", got)
	}

	rawRecord, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(rawRecord))
	var entry *record.Entry
	for scanner.Scan() {
		var e record.Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("decode JSONL record %q: %v", scanner.Text(), err)
		}
		if e.Host == "example.com" && e.URI == "/" {
			entry = &e
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan JSONL: %v", err)
	}
	if entry == nil {
		t.Fatalf("no GET / entry for example.com in JSONL: %s", rawRecord)
	}
	if entry.Mode != "mitm" || entry.Method != http.MethodGet || entry.Status != http.StatusOK {
		t.Fatalf("recorded entry = %+v, want mitm GET 200", entry)
	}
	if entry.RespBody != upstreamBody {
		t.Fatalf("recorded resp_body = %q, want %q", entry.RespBody, upstreamBody)
	}
}

// TestH2RecordsPlaintextForCompressedResponse verifies that the JSONL record
// holds the plaintext of a compressed response even when no script response
// hook runs, while the client still receives the original compressed bytes.
func TestH2RecordsPlaintextForCompressedResponse(t *testing.T) {
	compressed := gzipBody(t, upstreamBody)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
		_, _ = w.Write(compressed)
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	upstream.Listener = ln
	upstream.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	certDir := t.TempDir()
	certMgr, err := certmgr.LoadOrCreate(certDir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read test CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append test CA to root pool")
	}

	recordPath := filepath.Join(t.TempDir(), "rec.jsonl")
	recordFile, err := os.Create(recordPath)
	if err != nil {
		t.Fatalf("create record file: %v", err)
	}
	defer recordFile.Close()

	// The upstream is bound to 127.0.0.1:443, so the fake DNS answer plus a
	// real dialer reach it; same wiring as TestH2ClientToHTTP1UpstreamRegression.
	h := &Handler{
		CertMgr: certMgr,
		Dialer: &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					client, server := net.Pipe()
					go serveFakeDNS(server, net.ParseIP("127.0.0.1"))
					return client, nil
				},
			},
		},
	}
	h.SetRuntime(filter.Parse([]string{"example.com"}), record.New(recordFile, 4096), 4096, true)

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer front.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, err := front.Accept()
		if err != nil {
			return
		}
		h.HandleConn(ctx, conn, "example.com:443", false)
	}()

	clientCfg := &tls.Config{
		ServerName: "example.com",
		RootCAs:    roots,
		NextProtos: []string{"h2"},
	}
	client := &http.Client{Transport: &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", front.Addr().String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, clientCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}}
	defer client.CloseIdleConnections()

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Setting Accept-Encoding ourselves stops the client transport from
	// transparently decompressing, so the body read below is what actually
	// went on the wire between tlsdump and the client.
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	wire, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read client body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; X-Tlsdump-Error = %q", resp.StatusCode, resp.Header.Get("X-Tlsdump-Error"))
	}
	if string(wire) == upstreamBody {
		t.Fatal("client received plaintext, want the original compressed bytes")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("wire Content-Encoding = %q, want gzip", got)
	}
	decoded, _, err := decompressBody(wire, "gzip")
	if err != nil {
		t.Fatalf("client-side decompression of the wire body: %v", err)
	}
	if string(decoded) != upstreamBody {
		t.Fatalf("decoded wire body = %q, want %q", decoded, upstreamBody)
	}

	rawRecord, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(rawRecord))
	var entry *record.Entry
	for scanner.Scan() {
		var e record.Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("decode JSONL record %q: %v", scanner.Text(), err)
		}
		if e.Host == "example.com" && e.URI == "/" {
			entry = &e
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan JSONL: %v", err)
	}
	if entry == nil {
		t.Fatalf("no GET / entry for example.com in JSONL: %s", rawRecord)
	}
	if entry.RespBody != upstreamBody {
		t.Fatalf("recorded resp_body = %q, want plaintext %q", entry.RespBody, upstreamBody)
	}
	if entry.RespTrunc {
		t.Fatal("record marked truncated")
	}
	if got := entry.RespHeaders.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("recorded Content-Encoding = %q, want gzip", got)
	}
}

// serveFakeDNS answers A queries with the loopback test upstream's IP. It
// speaks both UDP and TCP DNS framing because net.Dialer's Go resolver can
// fall back from UDP to TCP. The connection port stays 443: the upstream is
// started on that port by the test, so no address rewriting is needed.
func serveFakeDNS(conn net.Conn, ip net.IP) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		reply, err := dnsReply(buf[:n], ip)
		if err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}

func dnsReply(query []byte, ip net.IP) ([]byte, error) {
	if len(query) < 12 {
		return nil, io.ErrUnexpectedEOF
	}
	payload := query
	framed := false
	if int(binary.BigEndian.Uint16(query[:2])) == len(query)-2 {
		var p dnsmessage.Parser
		h, err := p.Start(query[2:])
		if err == nil && !h.Response {
			if _, err := p.Question(); err == nil {
				payload, framed = query[2:], true
			}
		}
	}
	reply, err := dnsReplyBytes(payload, ip)
	if err != nil {
		return nil, err
	}
	if !framed {
		return reply, nil
	}
	out := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(out, uint16(len(reply)))
	copy(out[2:], reply)
	return out, nil
}

func dnsReplyBytes(query []byte, ip net.IP) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	// dnsPacketRoundTrip consumes one question while validating the reply,
	// then exchange calls SkipQuestion; the duplicate keeps section counts
	// consistent with the resolver's parser.
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA {
		var a dnsmessage.AResource
		copy(a.A[:], ip.To4())
		if err := b.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, a); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
