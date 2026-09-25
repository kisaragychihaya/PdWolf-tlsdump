package tun

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func buildTCP(src, dst tcpip.Address, srcPort, dstPort uint16, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcpHdr := header.TCP(b[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(b[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(header.TCPMinimumSize+len(payload)))
	xsum = checksum.Combine(xsum, checksum.Checksum(payload, 0))
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))
	return b
}

// newTestStack builds the same netstack configuration as Run (channel
// endpoint, promiscuous + spoofing NIC, default route) without a real tun
// device.
func newTestStack(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	linkEP := channel.New(channelQueueSize, defaultMTU, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"))
	if terr := s.CreateNIC(nicID, linkEP); terr != nil {
		t.Fatalf("CreateNIC: %v", terr)
	}
	if terr := s.SetPromiscuousMode(nicID, true); terr != nil {
		t.Fatalf("SetPromiscuousMode: %v", terr)
	}
	if terr := s.SetSpoofing(nicID, true); terr != nil {
		t.Fatalf("SetSpoofing: %v", terr)
	}
	addr := tcpip.AddrFrom4([4]byte{tunIPv4, tunIPa, tunIPb, tunIPc})
	if terr := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); terr != nil {
		t.Fatalf("AddProtocolAddress: %v", terr)
	}
	_, subnet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	mask, terr := tcpip.NewSubnet(
		tcpip.AddrFromSlice(subnet.IP.To4()),
		tcpip.MaskFromBytes(subnet.Mask),
	)
	if terr != nil {
		t.Fatalf("NewSubnet: %v", terr)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: mask, NIC: nicID}})
	return s, linkEP
}

// TestForwarderPipeline drives a full 3-way handshake through the netstack
// and verifies bidirectional data flow, mirroring what Run sets up with a
// real tun device.
func TestForwarderPipeline(t *testing.T) {
	s, linkEP := newTestStack(t)
	defer s.Close()

	accepted := make(chan *gonet.TCPConn, 1)
	fwd := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		wq := &waiter.Queue{}
		ep, terr := r.CreateEndpoint(wq)
		if terr != nil {
			t.Logf("CreateEndpoint failed: %v", terr)
			r.Complete(true)
			return
		}
		r.Complete(false)
		accepted <- gonet.NewTCPConn(wq, ep)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	src := tcpip.AddrFrom4([4]byte{192, 168, 50, 20})
	dst := tcpip.AddrFrom4([4]byte{93, 184, 216, 34})
	const clientPort = 40000
	const clientISN = 100

	inject := func(raw []byte) {
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: reserveHeader,
			Payload:            buffer.MakeWithData(raw),
		})
		linkEP.InjectInbound(ipv4.ProtocolNumber, pb)
		pb.DecRef()
	}
	readOutbound := func(timeout time.Duration) *stack.PacketBuffer {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return linkEP.ReadContext(ctx)
	}

	// 1. client SYN
	inject(buildTCP(src, dst, clientPort, 443, clientISN, 0, header.TCPFlagSyn, nil))

	// 2. expect SYN-ACK
	pkt := readOutbound(2 * time.Second)
	if pkt == nil {
		t.Fatal("no SYN-ACK after client SYN")
	}
	th := header.TCP(pkt.TransportHeader().Slice())
	if !th.Flags().Contains(header.TCPFlagSyn) || !th.Flags().Contains(header.TCPFlagAck) {
		t.Fatalf("expected SYN-ACK, got flags %s", th.Flags())
	}
	if got := header.IPv4(pkt.NetworkHeader().Slice()).SourceAddress(); got != dst {
		t.Fatalf("SYN-ACK src = %s, want spoofed original dst %s", got, dst)
	}
	serverISN := th.SequenceNumber()
	pkt.DecRef()

	// 3. final ACK completes the handshake
	inject(buildTCP(src, dst, clientPort, 443, clientISN+1, serverISN+1, header.TCPFlagAck, nil))

	var conn *gonet.TCPConn
	select {
	case conn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder did not accept the connection")
	}
	defer conn.Close()

	// 4. client -> server data through the stack
	inject(buildTCP(src, dst, clientPort, 443, clientISN+1, serverISN+1, header.TCPFlagAck|header.TCPFlagPsh, []byte("hello")))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read from accepted conn: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want %q", buf[:n], "hello")
	}

	// 5. server -> client data leaves the stack with the spoofed source.
	// Drain outbound packets until the one carrying our payload shows up
	// (pure ACKs may be emitted for earlier segments).
	if _, err := conn.Write([]byte("world")); err != nil {
		t.Fatalf("write to accepted conn: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("no outbound data packet carried the server payload")
		}
		pkt = readOutbound(remaining)
		if pkt == nil {
			t.Fatal("no outbound data packet after server write")
		}
		var payload bytes.Buffer
		_, _ = pkt.Data().ReadTo(&payload, true)
		if bytes.Contains(payload.Bytes(), []byte("world")) {
			ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
			if ipHdr.SourceAddress() != dst || ipHdr.DestinationAddress() != src {
				t.Fatalf("data packet %s -> %s, want %s -> %s", ipHdr.SourceAddress(), ipHdr.DestinationAddress(), dst, src)
			}
			pkt.DecRef()
			break
		}
		pkt.DecRef()
	}
	t.Log("full handshake and bidirectional data flow verified")
}
