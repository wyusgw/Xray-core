package hysteria

import (
	"context"
	gotls "crypto/tls"
	go_errors "errors"
	"math/rand"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

const (
	controlTimeout   = 10 * time.Second
	maxDatagramFrame = 1200
	defaultALPN      = "hysteria"

	// The flow control windows of the reference client.
	streamWindow = 15728640
	connWindow   = 67108864
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

// Handler is the first-generation outbound. It keeps one QUIC session to the
// server and opens a stream on it for each connection.
//
// It needs no `streamSettings`: there is no Xray transport underneath it, as
// with mieru. It still borrows the socket options when a profile supplies
// them, because those keep the connection from being looped back into the
// app's own TUN device.
type Handler struct {
	config         *ClientConfig
	server         *protocol.ServerSpec
	policyManager  policy.Manager
	dnsClient      dns.Client
	socketSettings *internet.SocketConfig
	tlsConfig      *gotls.Config

	mu   sync.Mutex
	link *serverLink
}

func NewClient(ctx context.Context, config *ClientConfig) (*Handler, error) {
	if config == nil || config.Server == nil {
		return nil, newError("no server specified")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if config.UpBps == 0 || config.DownBps == 0 {
		return nil, newError("up and down speed are required")
	}

	serverName := config.ServerName
	if serverName == "" && config.Server.Address.AsAddress().Family().IsDomain() {
		serverName = config.Server.Address.AsAddress().Domain()
	}
	alpn := config.Alpn
	if len(alpn) == 0 {
		alpn = []string{defaultALPN}
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		config:        config,
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		dnsClient:     v.GetFeature(dns.ClientType()).(dns.Client),
		tlsConfig: &gotls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: config.AllowInsecure,
			NextProtos:         alpn,
			MinVersion:         gotls.VersionTLS13,
		},
	}
	if streamSettings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok && streamSettings != nil {
		handler.socketSettings = streamSettings.SocketSettings
	}
	return handler, nil
}

// serverLink is a QUIC session that has passed the hello, with the sessions of
// UDP it carries.
type serverLink struct {
	conn    *quic.Conn
	tr      *quic.Transport
	pktConn net.PacketConn

	sync.Mutex
	udp    map[uint32]chan *udpMessage
	closed bool
}

func (l *serverLink) alive() bool {
	select {
	case <-l.conn.Context().Done():
		return false
	default:
		return true
	}
}

func (l *serverLink) close() {
	_ = l.conn.CloseWithError(0, "")
	_ = l.tr.Close()
	_ = l.pktConn.Close()
}

// receive hands each datagram to the UDP session it names, until the QUIC
// session ends.
func (l *serverLink) receive() {
	for {
		datagram, err := l.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		msg, err := parseUDPMessage(datagram)
		if err != nil {
			continue
		}
		l.Lock()
		ch := l.udp[msg.SessionID]
		l.Unlock()
		if ch == nil {
			continue
		}
		select {
		case ch <- msg:
		default:
		}
	}
}

func (l *serverLink) register(id uint32) (chan *udpMessage, error) {
	l.Lock()
	defer l.Unlock()
	if l.closed {
		return nil, newError("session closed")
	}
	ch := make(chan *udpMessage, 1024)
	l.udp[id] = ch
	return ch, nil
}

func (l *serverLink) unregister(id uint32) {
	l.Lock()
	delete(l.udp, id)
	l.Unlock()
}

// connect returns the live session to the server, dialing one when there is
// none. The hello of a dead session is never reused.
func (h *Handler) connect(ctx context.Context) (*serverLink, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.link != nil {
		if h.link.alive() {
			return h.link, nil
		}
		h.link.close()
		h.link = nil
	}
	link, err := h.dial(ctx)
	if err != nil {
		return nil, err
	}
	h.link = link
	return link, nil
}

func (h *Handler) resolve() (net.IP, error) {
	address := h.server.Destination.Address
	if address.Family().IsIP() {
		return address.IP(), nil
	}
	ips, _, err := h.dnsClient.LookupIP(address.Domain(), dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, newError("no address for ", address.Domain())
	}
	return ips[0], nil
}

func (h *Handler) dial(ctx context.Context) (*serverLink, error) {
	ip, err := h.resolve()
	if err != nil {
		return nil, errors.New("failed to resolve the server").Base(err)
	}
	dest := net.UDPDestination(net.IPAddress(ip), h.server.Destination.Port)

	var pktConn net.PacketConn
	var udpAddr net.Addr
	rawConn, err := internet.DialSystem(ctx, dest, h.socketSettings)
	if err != nil {
		return nil, errors.New("failed to dial the server").Base(err)
	}
	switch c := rawConn.(type) {
	case *net.PacketConnWrapper:
		pktConn = c.PacketConn
		udpAddr = c.RemoteAddr()
	case *cnc.Connection:
		pktConn = &internet.FakePacketConn{Conn: c}
		udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
	default:
		_ = rawConn.Close()
		return nil, newError("unexpected socket ", reflect.TypeOf(c))
	}
	if h.config.ObfsPassword != "" {
		pktConn = newXPlusConn(pktConn, h.config.ObfsPassword)
	}

	tr := &quic.Transport{Conn: pktConn}
	fail := func(conn *quic.Conn, code quic.ApplicationErrorCode, err error) (*serverLink, error) {
		if conn != nil {
			_ = conn.CloseWithError(code, "")
		}
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, err
	}

	conn, err := tr.Dial(ctx, udpAddr, h.tlsConfig, &quic.Config{
		InitialStreamReceiveWindow:     streamWindow,
		MaxStreamReceiveWindow:         streamWindow,
		InitialConnectionReceiveWindow: connWindow,
		MaxConnectionReceiveWindow:     connWindow,
		MaxIdleTimeout:                 20 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		DisablePathMTUDiscovery:        runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin",
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           maxDatagramFrame,
		DisablePathManager:             true,
	})
	if err != nil {
		return fail(nil, 0, errors.New("quic handshake failed").Base(err))
	}

	openCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	stream, err := conn.OpenStreamSync(openCtx)
	cancel()
	if err != nil {
		return fail(conn, closeCodeProtocol, err)
	}
	_ = stream.SetDeadline(time.Now().Add(controlTimeout))
	if err := writeClientHello(stream, h.config.UpBps, h.config.DownBps, []byte(h.config.Auth)); err != nil {
		return fail(conn, closeCodeProtocol, err)
	}
	ok, recvBPS, message, err := readServerHello(stream)
	if err != nil {
		return fail(conn, closeCodeProtocol, err)
	}
	if !ok {
		return fail(conn, closeCodeAuth, newError("auth failed: ", message))
	}
	_ = stream.SetDeadline(time.Time{})

	// The client sends at the rate the server says it can receive.
	if recvBPS == 0 {
		congestion.UseBBR(conn, bbr.ProfileStandard)
	} else {
		congestion.UseBrutal(conn, recvBPS, false)
	}

	link := &serverLink{conn: conn, tr: tr, pktConn: pktConn, udp: map[uint32]chan *udpMessage{}}
	go func() {
		link.receive()
		link.Lock()
		link.closed = true
		link.Unlock()
	}()
	return link, nil
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return newError("invalid outbound target")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return newError("target not specified")
	}
	ob.Name = protocolName
	ob.CanSpliceCopy = 3
	target := ob.Target

	server, err := h.connect(ctx)
	if err != nil {
		return err
	}
	stream, err := server.conn.OpenStreamSync(ctx)
	if err != nil {
		return errors.New("failed to open a stream").Base(err)
	}
	defer func() {
		stream.CancelRead(0)
		_ = stream.Close()
	}()
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", h.server.Destination.NetAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}
	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)
	if newCtx != nil {
		ctx = newCtx
	}

	if target.Network == net.Network_TCP {
		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			writer := buf.NewBufferedWriter(buf.NewWriter(stream))
			if err := writeRequest(writer, false, target.NetAddr()); err != nil {
				return errors.New("failed to write request").Base(err)
			}
			if err := writer.SetBuffered(false); err != nil {
				return err
			}
			return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
		}
		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			ok, _, message, err := readResponse(stream)
			if err != nil {
				return err
			}
			if !ok {
				return newError(message)
			}
			return buf.Copy(buf.NewReader(stream), link.Writer, buf.UpdateActivity(timer))
		}
		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}
		return nil
	}

	if target.Network == net.Network_UDP {
		if err := writeRequest(stream, true, ""); err != nil {
			return errors.New("failed to write request").Base(err)
		}
		ok, id, message, err := readResponse(stream)
		if err != nil {
			return errors.New("failed to read response").Base(err)
		}
		if !ok {
			return newError("udp rejected: ", message)
		}
		incoming, err := server.register(id)
		if err != nil {
			return err
		}
		defer server.unregister(id)

		// The server keeps the session only while this stream is open.
		go func() {
			var sink [64]byte
			for {
				if _, err := stream.Read(sink[:]); err != nil {
					cancel()
					return
				}
			}
		}()

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			writer := &udpWriter{conn: server.conn, id: id, addr: target.NetAddr()}
			if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP request").Base(err)
			}
			return nil
		}
		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			reader := &udpReader{ctx: ctx, incoming: incoming, df: &defragger{}}
			if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP response").Base(err)
			}
			return nil
		}
		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}
	}
	return nil
}

// udpWriter sends each packet as a message of the session the server named.
type udpWriter struct {
	conn *quic.Conn
	id   uint32
	addr string
	buf  [buf.Size]byte
}

func (w *udpWriter) send(msg *udpMessage) error {
	n := msg.serialize(w.buf[:])
	if n < 0 {
		return nil
	}
	return w.conn.SendDatagram(w.buf[:n])
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		addr := w.addr
		if b.UDP != nil {
			addr = b.UDP.NetAddr()
		}
		host, portText, err := net.SplitHostPort(addr)
		port, portErr := net.PortFromString(portText)
		if err != nil || portErr != nil {
			b.Release()
			continue
		}

		msg := &udpMessage{SessionID: w.id, Host: host, Port: port.Value(), FragCount: 1, Data: b.Bytes()}
		err = w.send(msg)
		var tooLarge *quic.DatagramTooLargeError
		if go_errors.As(err, &tooLarge) {
			msg.MsgID = uint16(rand.Intn(0xFFFF)) + 1
			for _, frag := range fragment(*msg, int(tooLarge.MaxDatagramPayloadSize)) {
				if err := w.send(&frag); err != nil {
					buf.ReleaseMulti(mb[i:])
					return err
				}
			}
		} else if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

type udpReader struct {
	ctx      context.Context
	incoming <-chan *udpMessage
	df       *defragger
}

func (r *udpReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		var msg *udpMessage
		select {
		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		case msg = <-r.incoming:
		}
		whole := r.df.feed(msg)
		if whole == nil {
			continue
		}
		dest, err := net.ParseDestination("udp:" + net.JoinHostPort(whole.Host, strconv.Itoa(int(whole.Port))))
		if err != nil || len(whole.Data) > buf.Size {
			continue
		}
		b := buf.New()
		_, _ = b.Write(whole.Data)
		b.UDP = &dest
		return buf.MultiBuffer{b}, nil
	}
}
