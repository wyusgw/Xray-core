package mieru

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

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
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

// Handler is the mieru outbound.
//
// mieru carries traffic over its own obfuscated transport and does its own
// dialing, so unlike most outbounds here it needs no `streamSettings`: there is
// no Xray transport underneath it. It still borrows the socket options when a
// profile happens to supply them, because those are what keep the connection
// from being looped back into the app's own TUN device.
type Handler struct {
	config        *ClientConfig
	account       *MemoryAccount
	policyManager policy.Manager
	level         uint32

	socketSettings *internet.SocketConfig
	dnsClient      dns.Client

	mu     sync.Mutex
	client mieruclient.Client
}

func NewClient(ctx context.Context, config *ClientConfig) (*Handler, error) {
	if config == nil || config.Server == nil {
		return nil, newError("no server specified")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, newError("no user specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, newError("invalid account type")
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		config:        config,
		account:       account,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		level:         server.User.Level,
		dnsClient:     v.GetFeature(dns.ClientType()).(dns.Client),
	}
	if streamSettings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok && streamSettings != nil {
		handler.socketSettings = streamSettings.SocketSettings
	}
	return handler, nil
}

// mieruProfile translates the outbound config into the profile mieru's own
// client API expects.
func (h *Handler) mieruProfile() (*appctlpb.ClientProfile, error) {
	address := h.config.Server.Address.AsAddress()
	endpoint := &appctlpb.ServerEndpoint{}
	if address.Family().IsDomain() {
		endpoint.DomainName = proto.String(address.Domain())
	} else {
		endpoint.IpAddress = proto.String(address.IP().String())
	}

	transportProtocol := appctlpb.TransportProtocol_TCP
	if strings.EqualFold(h.config.Transport, "UDP") {
		transportProtocol = appctlpb.TransportProtocol_UDP
	}
	binding := &appctlpb.PortBinding{Protocol: transportProtocol.Enum()}
	if h.config.PortRangeStart != 0 && h.config.PortRangeEnd != 0 {
		// mieru spells a range as a single "start-end" string.
		binding.PortRange = proto.String(
			strconv.FormatUint(uint64(h.config.PortRangeStart), 10) +
				"-" + strconv.FormatUint(uint64(h.config.PortRangeEnd), 10),
		)
	} else {
		binding.Port = proto.Int32(int32(h.config.Server.Port))
	}
	endpoint.PortBindings = []*appctlpb.PortBinding{binding}

	profile := &appctlpb.ClientProfile{
		ProfileName: proto.String(protocolName),
		User: &appctlpb.User{
			Name:     proto.String(h.account.Username),
			Password: proto.String(h.account.Password),
		},
		Servers: []*appctlpb.ServerEndpoint{endpoint},
	}
	if h.config.Mtu != 0 {
		profile.Mtu = proto.Int32(h.config.Mtu)
	}
	if h.config.Multiplexing != "" {
		level, ok := appctlpb.MultiplexingLevel_value[h.config.Multiplexing]
		if !ok {
			return nil, newError("unsupported multiplexing level ", h.config.Multiplexing)
		}
		profile.Multiplexing = &appctlpb.MultiplexingConfig{
			Level: appctlpb.MultiplexingLevel(level).Enum(),
		}
	}
	if h.config.HandshakeMode != "" {
		mode, ok := appctlpb.HandshakeMode_value[h.config.HandshakeMode]
		if !ok {
			return nil, newError("unsupported handshake mode ", h.config.HandshakeMode)
		}
		profile.HandshakeMode = appctlpb.HandshakeMode(mode).Enum()
	}
	return profile, nil
}

// mieruClient starts the underlying client on first use. Building it eagerly in
// NewClient would open sockets while the config is still being loaded, and every
// node in a profile is constructed even though only one of them is selected.
func (h *Handler) mieruClient() (mieruclient.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client != nil {
		return h.client, nil
	}
	profile, err := h.mieruProfile()
	if err != nil {
		return nil, err
	}
	dialer := &systemDialer{socketSettings: h.socketSettings}
	client := mieruclient.NewClient()
	if err := client.Store(&mieruclient.ClientConfig{
		Profile:      profile,
		Dialer:       dialer,
		PacketDialer: dialer,
		Resolver:     xrayResolver{client: h.dnsClient},
		// The dialer already resolves through Xray, so mieru must hand it the
		// server name untouched rather than resolving separately and losing the
		// routing and DNS rules the user configured.
		DNSConfig: &apicommon.ClientDNSConfig{BypassDialerDNS: true},
	}); err != nil {
		return nil, errors.New("failed to store mieru client config").Base(err)
	}
	if err := client.Start(); err != nil {
		return nil, errors.New("failed to start mieru client").Base(err)
	}
	h.client = client
	return client, nil
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
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

	client, err := h.mieruClient()
	if err != nil {
		return err
	}

	destination := model.NetAddrSpec{
		AddrSpec: model.AddrSpec{Port: int(target.Port.Value())},
		Net:      target.Network.SystemString(),
	}
	if target.Address.Family().IsDomain() {
		// Leave the name unresolved: mieru forwards it to the server, which is
		// the whole point of proxying by domain.
		destination.FQDN = target.Address.Domain()
	} else {
		destination.IP = target.Address.IP()
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(h.level)
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

	conn, err := client.DialContext(ctx, destination)
	if err != nil {
		return errors.New("failed to connect through mieru").AtWarning().Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via mieru")

	switch target.Network {
	case net.Network_TCP:
		return h.processTCP(ctx, link, conn, sessionPolicy, timer)
	case net.Network_UDP:
		return h.processUDP(ctx, link, conn, target, sessionPolicy, timer)
	default:
		return newError("unsupported network ", target.Network)
	}
}

func (h *Handler) processTCP(ctx context.Context, link *transport.Link, conn net.Conn, sessionPolicy policy.Session, timer *signal.ActivityTimer) error {
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

func (h *Handler) processUDP(ctx context.Context, link *transport.Link, conn net.Conn, target net.Destination, sessionPolicy policy.Session, timer *signal.ActivityTimer) error {
	// mieru hands back a stream even for a UDP destination, so packets need two
	// layers on top of it: PacketOverStreamTunnel to keep their boundaries, and
	// UDPAssociateWrapper to carry the per-packet destination in a socks5
	// UDP-associate header.
	packetConn := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(conn))

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		writer := &udpPacketWriter{conn: packetConn, destination: target}
		if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all UDP request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		reader := &udpPacketReader{conn: packetConn, destination: target}
		if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all UDP response").Base(err)
		}
		return nil
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

// Close releases the mieru client when the outbound handler is removed, for
// example on a config reload. mieru clients cannot be restarted, so the field is
// cleared and the next request builds a fresh one.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client == nil {
		return nil
	}
	err := h.client.Stop()
	h.client = nil
	return err
}

type udpPacketWriter struct {
	conn        net.PacketConn
	destination net.Destination
}

func (w *udpPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, buffer := range mb {
		destination := w.destination
		if buffer.UDP != nil {
			destination = *buffer.UDP
		}
		if !destination.IsValid() {
			buffer.Release()
			continue
		}
		if _, err := w.conn.WriteTo(buffer.Bytes(), mieruAddr(destination)); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		buffer.Release()
	}
	return nil
}

type udpPacketReader struct {
	conn        net.PacketConn
	destination net.Destination
}

func (r *udpPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := r.conn.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))

	// The wrapper reports the origin of each packet. Fall back to the session
	// destination when it is not something Xray can express, so a reply is
	// delivered rather than dropped.
	source := r.destination
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr != nil && len(udpAddr.IP) > 0 {
		source = net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port))
	}
	b.UDP = &source
	return buf.MultiBuffer{b}, nil
}

// mieruAddr converts an Xray destination into the address type mieru's socks5
// layer understands, keeping domain names unresolved.
func mieruAddr(destination net.Destination) model.NetAddrSpec {
	addr := model.NetAddrSpec{
		AddrSpec: model.AddrSpec{Port: int(destination.Port.Value())},
		Net:      "udp",
	}
	if destination.Address.Family().IsDomain() {
		addr.FQDN = destination.Address.Domain()
	} else {
		addr.IP = destination.Address.IP()
	}
	return addr
}

// systemDialer lets mieru reach its own server through Xray's dialer, so the
// connection picks up the socket options that keep it outside the app's TUN and
// resolves names with Xray's DNS instead of the host resolver.
type systemDialer struct {
	socketSettings *internet.SocketConfig
}

func (d *systemDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dest, err := net.ParseDestination(network + ":" + address)
	if err != nil {
		return nil, err
	}
	return internet.DialSystem(ctx, dest, d.socketSettings)
}

func (d *systemDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (net.PacketConn, error) {
	dest, err := net.ParseDestination(network + ":" + raddr)
	if err != nil {
		return nil, err
	}
	conn, err := internet.DialSystem(ctx, dest, d.socketSettings)
	if err != nil {
		return nil, err
	}
	switch c := conn.(type) {
	case *internet.PacketConnWrapper:
		return c.PacketConn, nil
	case *cnc.Connection:
		return &internet.FakePacketConn{Conn: c}, nil
	default:
		conn.Close()
		return nil, newError("unexpected packet connection type ", fmt.Sprintf("%T", conn))
	}
}

// xrayResolver resolves the mieru server's name with Xray's own DNS client, so
// the lookup follows the profile's DNS and routing rules.
type xrayResolver struct {
	client dns.Client
}

func (r xrayResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	option := dns.IPOption{IPv4Enable: true, IPv6Enable: true}
	switch network {
	case "ip4":
		option.IPv6Enable = false
	case "ip6":
		option.IPv4Enable = false
	}
	ips, _, err := r.client.LookupIP(host, option)
	return ips, err
}
