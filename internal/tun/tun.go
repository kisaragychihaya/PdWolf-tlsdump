// Package tun implements transparent traffic capture using a virtual NIC
// (wintun on Windows, /dev/net/tun elsewhere) and the gVisor netstack.
package tun

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"tlsdump/internal/mitm"
)

const (
	defaultMTU        = 1420
	defaultUDPTimeout = 2 * time.Minute

	tunOffset        = 4
	reserveHeader    = 64
	nicID            = 1
	channelQueueSize = 512

	tunIPv4 = 198
	tunIPa  = 19
	tunIPb  = 0
	tunIPc  = 1
)

// Config controls Run.
type Config struct {
	Name           string
	MTU            int
	Handler        *mitm.Handler
	NoRoute        bool
	PhysicalIface  string
	ExcludeDomains []string
	UDPTimeout     time.Duration
}

func (c *Config) withDefaults() {
	if c.Name == "" {
		c.Name = "tlsdump"
	}
	if c.MTU <= 0 {
		c.MTU = defaultMTU
	}
	if c.UDPTimeout <= 0 {
		c.UDPTimeout = defaultUDPTimeout
	}
}

// Run creates the TUN device, sets up the netstack and blocks until ctx is
// cancelled.
func Run(ctx context.Context, cfg Config) error {
	cfg.withDefaults()
	if cfg.Handler == nil {
		return errors.New("tun: Handler is nil")
	}
	if err := preparePlatform(cfg.Name); err != nil {
		return fmt.Errorf("tun: platform setup: %w", err)
	}

	physName := cfg.PhysicalIface
	if physName == "" {
		physName = defaultRouteInterface(cfg.Name)
	}

	// Pin excluded domains' IPs to the physical interface with /32 host
	// routes so critical traffic (e.g. this session's own API calls) never
	// enters the tun. This must happen BEFORE the tun device and catch
	// routes exist: DNS resolution only works reliably on the pristine
	// network, and the /32 routes must be in place before traffic can be
	// hijacked.
	var cleanups []func() error
	runCleanups := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				slog.Warn("tun: route cleanup failed", "err", err)
			}
		}
	}
	fail := func(err error) error {
		runCleanups()
		return err
	}

	if !cfg.NoRoute && len(cfg.ExcludeDomains) > 0 {
		exCleanup, err := addExcludes(cfg.ExcludeDomains, physName)
		if err != nil {
			slog.Warn("tun: excludes not applied", "err", err)
		} else if exCleanup != nil {
			cleanups = append(cleanups, exCleanup)
		}
	}

	dev, err := tun.CreateTUN(tunCreateName(cfg.Name), cfg.MTU)
	if err != nil {
		return fail(err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return fail(err)
	}
	slog.Info("tun device created", "name", name, "mtu", cfg.MTU)

	if cfg.NoRoute {
		slog.Info("tun: skipping system route configuration (-tun-no-route)")
	} else {
		rtCleanup, err := setupRoutes(name)
		if err != nil {
			dev.Close()
			return fail(err)
		}
		cleanups = append(cleanups, rtCleanup)
	}

	// Bind outbound connections to the physical interface so packets do not
	// loop back into the tun interface.
	if cfg.Handler.Dialer == nil {
		cfg.Handler.Dialer = newBoundDialer(physName)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEP := channel.New(channelQueueSize, uint32(cfg.MTU), tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"))
	if terr := s.CreateNIC(nicID, linkEP); terr != nil {
		dev.Close()
		return fail(errors.New("tun: create NIC: " + terr.String()))
	}
	if terr := s.SetPromiscuousMode(nicID, true); terr != nil {
		slog.Warn("tun: set promiscuous mode failed", "err", terr.String())
	}
	// Forwarder endpoints bind foreign destination IPs as their local
	// address; spoofing is required for the stack to send from those.
	if terr := s.SetSpoofing(nicID, true); terr != nil {
		slog.Warn("tun: set spoofing failed", "err", terr.String())
	}
	addr := tcpip.AddrFrom4([4]byte{tunIPv4, tunIPa, tunIPb, tunIPc})
	if terr := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); terr != nil {
		slog.Warn("tun: add address failed", "err", terr.String())
	}
	_, defaultSubnet, serr := net.ParseCIDR("0.0.0.0/0")
	if serr != nil {
		panic(serr) // constant CIDR, cannot fail
	}
	mask, _ := tcpip.NewSubnet(
		tcpip.AddrFromSlice(defaultSubnet.IP.To4()),
		tcpip.MaskFromBytes(defaultSubnet.Mask),
	)
	s.SetRouteTable([]tcpip.Route{{Destination: mask, NIC: nicID}})

	st := &bridgeStats{}
	installTCPForwarder(ctx, s, cfg, st)
	installUDPForwarder(ctx, s, cfg)

	errCh := make(chan error, 2)
	go bridgeDownlink(dev, linkEP, cfg.MTU, errCh, st)
	go bridgeUplink(ctx, dev, linkEP, errCh, st)

	// Periodic diagnostics: these counts pinpoint where the pipeline breaks.
	statsDone := make(chan struct{})
	defer close(statsDone)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-statsDone:
				return
			case <-t.C:
				slog.Info("tun: stats", "dev-in", st.devIn.Load(), "injected", st.injected.Load(),
					"non-ip4-dropped", st.dropped.Load(), "netstack-out", st.out.Load(),
					"flows", st.flows.Load(), "rejected-syn", st.rejected.Load())
			}
		}
	}()

	slog.Info("tun: running", "device", name)
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	slog.Info("tun: shutting down", "device", name)
	dev.Close()
	runCleanups()
	s.Close()
	if runErr != nil {
		return runErr
	}
	return ctx.Err()
}

// installTCPForwarder routes every accepted TCP connection into the mitm
// handler with the original destination address.
func installTCPForwarder(ctx context.Context, s *stack.Stack, cfg Config, st *bridgeStats) {
	fwd := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		// ID must be captured before CreateEndpoint/Complete: Complete
		// releases the underlying segment.
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		wq := &waiter.Queue{}
		ep, terr := r.CreateEndpoint(wq)
		if terr != nil {
			slog.Debug("tun: forwarder CreateEndpoint failed", "err", terr.String())
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(wq, ep)
		st.flows.Add(1)
		slog.Debug("tun: new flow", "dst", dst, "client", id.RemoteAddress.String())
		go cfg.Handler.HandleConn(ctx, conn, dst, false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if ok := fwd.HandlePacket(id, pkt); ok {
			return true
		}
		// Log why SYN-looking segments are refused (checksum, flags, ...).
		if th := pkt.TransportHeader().Slice(); len(th) >= header.TCPMinimumSize {
			flags := header.TCP(th).Flags()
			if flags.Contains(header.TCPFlagSyn) && !flags.Contains(header.TCPFlagAck) {
				st.rejected.Add(1)
				slog.Info("tun: forwarder rejected SYN", "src", id.RemoteAddress, "dst", id.LocalAddress,
					"flags", flags, "segLen", pkt.Data().Size()+len(th), "cksum", header.TCP(th).Checksum())
			}
		}
		return false
	})
}

// installUDPForwarder relays UDP flows (DNS etc.) to their original
// destination with an idle timeout.
func installUDPForwarder(ctx context.Context, s *stack.Stack, cfg Config) {
	fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		wq := &waiter.Queue{}
		ep, terr := r.CreateEndpoint(wq)
		if terr != nil {
			slog.Debug("tun: UDP endpoint create failed", "err", terr.String())
			return
		}
		conn := gonet.NewUDPConn(wq, ep)
		go relayUDP(ctx, conn, dst, cfg)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

// relayUDP copies packets both ways between the netstack UDP socket and the
// real destination, closing both sides after an idle period.
func relayUDP(ctx context.Context, conn *gonet.UDPConn, dst string, cfg Config) {
	defer conn.Close()
	var d net.Dialer
	if cfg.Handler.Dialer != nil {
		d = *cfg.Handler.Dialer
	}
	d.Timeout = cfg.UDPTimeout
	upstream, err := d.DialContext(ctx, "udp", dst)
	if err != nil {
		slog.Debug("tun: UDP dial failed", "dst", dst, "err", err)
		return
	}
	defer upstream.Close()

	timer := time.AfterFunc(cfg.UDPTimeout, func() {
		conn.Close()
		upstream.Close()
	})
	defer timer.Stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&activityWriter{w: upstream, timer: timer, timeout: cfg.UDPTimeout}, &activityReader{r: conn, timer: timer, timeout: cfg.UDPTimeout})
		if u, ok := upstream.(*net.UDPConn); ok {
			_ = u.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&activityWriter{w: conn, timer: timer, timeout: cfg.UDPTimeout}, &activityReader{r: upstream, timer: timer, timeout: cfg.UDPTimeout})
	}()
	wg.Wait()
}

// bridgeStats counts packets crossing the tun bridges for diagnostics.
type bridgeStats struct {
	devIn    atomic.Int64
	injected atomic.Int64
	dropped  atomic.Int64
	out      atomic.Int64
	flows    atomic.Int64
	rejected atomic.Int64
}

// bridgeDownlink moves packets from the tun device into the netstack.
func bridgeDownlink(dev tun.Device, linkEP *channel.Endpoint, mtu int, errCh chan<- error, st *bridgeStats) {
	bufs := [][]byte{make([]byte, tunOffset+mtu+reserveHeader)}
	sizes := make([]int, 1)
	var logged int
	for {
		n, err := dev.Read(bufs, sizes, tunOffset)
		if err != nil {
			errCh <- err
			return
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			st.devIn.Add(1)
			pkt := bufs[i]
			if pkt[tunOffset]>>4 != 4 {
				st.dropped.Add(1)
				continue // not IPv4
			}
			if logged < 10 {
				logged++
				h := header.IPv4(pkt[tunOffset : tunOffset+sizes[i]])
				slog.Debug("tun: first inbound packets", "src", h.SourceAddress(), "dst", h.DestinationAddress(), "proto", h.Protocol(), "len", sizes[i])
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: reserveHeader,
				Payload:            buffer.MakeWithData(pkt[tunOffset : tunOffset+sizes[i]]),
			})
			linkEP.InjectInbound(ipv4.ProtocolNumber, pb)
			pb.DecRef()
			st.injected.Add(1)
		}
	}
}

// bridgeUplink moves packets written by the netstack out to the tun device.
func bridgeUplink(ctx context.Context, dev tun.Device, linkEP *channel.Endpoint, errCh chan<- error, st *bridgeStats) {
	var logged int
	for {
		pkt := linkEP.ReadContext(ctx)
		if pkt == nil {
			errCh <- ctx.Err()
			return
		}
		if logged < 10 {
			logged++
			h := header.IPv4(pkt.NetworkHeader().Slice())
			slog.Debug("tun: first outbound packets", "src", h.SourceAddress(), "dst", h.DestinationAddress(), "proto", h.TransportProtocol(), "len", pkt.Size())
		}
		netHdr := pkt.NetworkHeader().Slice()
		transHdr := pkt.TransportHeader().Slice()
		var payload bytes.Buffer
		_, _ = pkt.Data().ReadTo(&payload, true)
		frame := make([]byte, 0, tunOffset+len(netHdr)+len(transHdr)+payload.Len())
		frame = append(frame, make([]byte, tunOffset)...)
		frame = append(frame, netHdr...)
		frame = append(frame, transHdr...)
		frame = append(frame, payload.Bytes()...)
		if logged <= 3 {
			slog.Debug("tun: outbound frame hex", "data", hex.EncodeToString(frame[tunOffset:]))
		}
		if _, err := dev.Write([][]byte{frame}, tunOffset); err != nil {
			pkt.DecRef()
			errCh <- err
			return
		}
		pkt.DecRef()
		st.out.Add(1)
	}
}

// activityReader/activityWriter reset the idle timer on every packet.
type activityReader struct {
	r       io.Reader
	timer   *time.Timer
	timeout time.Duration
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.timer.Reset(a.timeout)
	}
	return n, err
}

type activityWriter struct {
	w       io.Writer
	timer   *time.Timer
	timeout time.Duration
}

func (a *activityWriter) Write(p []byte) (int, error) {
	n, err := a.w.Write(p)
	if n > 0 {
		a.timer.Reset(a.timeout)
	}
	return n, err
}
