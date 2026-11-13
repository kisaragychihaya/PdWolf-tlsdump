package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// upstreamProtos offers both HTTP/2 and HTTP/1.1 to the upstream. The
// negotiated protocol, not the client-side ALPN, decides which RoundTripper
// speaks to it: an HTTP/1.1-only upstream would otherwise be read as HTTP/2
// frames by a client that connected to tlsdump with h2.
var upstreamProtos = []string{"h2", "http/1.1"}

// upstreamDispatcher lazily probes the upstream ALPN once per client h2
// connection and dispatches all requests on that connection to the matching
// http.RoundTripper. Both transports are long lived so their connection pools
// are reused across requests; the probe connection is handed to the selected
// transport as its first pooled connection.
type upstreamDispatcher struct {
	h              *Handler
	ctx            context.Context
	addr           string
	serverName     string
	once           sync.Once
	transport      http.RoundTripper
	resolveErr     error
	mu             sync.Mutex
	probedConn     net.Conn
	probedConnUsed bool
}

// newUpstreamDispatcher returns a dispatcher for one terminated h2 client
// connection. serverName is the SNI (or destination host when there is none).
func newUpstreamDispatcher(ctx context.Context, h *Handler, addr, serverName string) *upstreamDispatcher {
	return &upstreamDispatcher{h: h, ctx: ctx, addr: addr, serverName: serverName}
}

// RoundTrip resolves the upstream protocol on the first call and forwards the
// request through the selected transport. A failed probe is sticky: every
// request on this client connection reports the same dial/handshake error.
func (d *upstreamDispatcher) RoundTrip(req *http.Request) (*http.Response, error) {
	d.once.Do(d.resolve)
	if d.resolveErr != nil {
		return nil, d.resolveErr
	}
	return d.transport.RoundTrip(req)
}

func (d *upstreamDispatcher) resolve() {
	conn, err := d.h.dialTLS(d.ctx, d.addr, d.serverName, upstreamProtos)
	if err != nil {
		d.resolveErr = err
		return
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		d.resolveErr = fmt.Errorf("upstream TLS dial returned %T, want *tls.Conn", conn)
		return
	}

	// A Go TLS server that supports none of the offered protocols leaves
	// NegotiatedProtocol empty; that is an HTTP/1.1-only upstream.
	proto := tlsConn.ConnectionState().NegotiatedProtocol
	if proto == "h2" {
		d.transport = &http2.Transport{DialTLSContext: d.dialTLS}
	} else {
		// The dial hook offers both protocols on later connections too. If a
		// server ever negotiates h2 there, net/http would try to speak h2 on
		// a connection this dispatcher selected for HTTP/1.1; disable it.
		d.transport = &http.Transport{
			DialTLSContext: d.dialHTTP1,
			TLSNextProto:   map[string]func(string, *tls.Conn) http.RoundTripper{},
		}
	}
	d.mu.Lock()
	d.probedConn = conn
	d.mu.Unlock()
}

// takeProbedConn hands the already-handshaked probe connection to the selected
// transport exactly once. Later dials establish fresh connections.
func (d *upstreamDispatcher) takeProbedConn() net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.probedConnUsed {
		return nil
	}
	conn := d.probedConn
	d.probedConnUsed = true
	d.probedConn = nil
	return conn
}

func (d *upstreamDispatcher) dialTLS(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return d.dial(ctx, addr)
}

func (d *upstreamDispatcher) dialHTTP1(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, addr)
}

func (d *upstreamDispatcher) dial(ctx context.Context, addr string) (net.Conn, error) {
	if conn := d.takeProbedConn(); conn != nil {
		return conn, nil
	}
	return d.h.dialTLS(ctx, addr, d.serverName, upstreamProtos)
}
