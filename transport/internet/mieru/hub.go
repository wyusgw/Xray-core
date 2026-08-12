package mieru

import (
	"context"
	gonet "net"
	"strings"
	"sync"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mierucommon "github.com/enfein/mieru/v3/pkg/common"
	mieruprotocol "github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Listener runs a mieru Mux and feeds the connections it accepts to the inbound
// handler.
//
// mieru binds its own sockets rather than riding on an Xray transport, so this
// is a listener in name and shape only: the Mux owns the underlay, and what
// comes out of Accept is an already-authenticated, already-decrypted stream. The
// socks5 request that follows is read by proxy/mieru, the same split mieru's own
// apis/server draws between Mux.Accept and Server.Accept.
type Listener struct {
	mux     *mieruprotocol.Mux
	manager UserManager
	addr    net.Addr
	cancel  context.CancelFunc

	closeOnce sync.Once
}

func (l *Listener) Addr() gonet.Addr {
	return l.addr
}

func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.cancel()
		// Detach first: the observer closes over the Mux, and the inbound outlives
		// the listener when only the stream settings change on a reload.
		if l.manager != nil {
			l.manager.SetMieruUserObserver(nil)
		}
		err = l.mux.Close()
	})
	return err
}

// Listen starts a mieru server on the inbound's address and port.
func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	manager := UserManagerFromContext(ctx)
	if manager == nil {
		return nil, errors.New("mieru requires a user manager from context")
	}

	settings := ServerSettingsFromContext(ctx)
	transport := appctlpb.TransportProtocol_TCP
	if strings.EqualFold(settings.Transport, "UDP") {
		transport = appctlpb.TransportProtocol_UDP
	}

	mtu := mierucommon.DefaultMTU
	if settings.MTU != 0 {
		mtu = int(settings.MTU)
	}

	// Built here rather than with appctlcommon.PortBindingsToUnderlayProperties,
	// which hardcodes 0.0.0.0 and would ignore the inbound's `listen` address.
	listenIP := address.IP()
	if address.Family().IsDomain() {
		return nil, errors.New("mieru cannot listen on a domain address: ", address)
	}
	var endpoint mieruprotocol.UnderlayProperties
	switch transport {
	case appctlpb.TransportProtocol_UDP:
		endpoint = mieruprotocol.NewUnderlayProperties(mtu, mierucommon.PacketTransport, &gonet.UDPAddr{IP: listenIP, Port: int(port)}, nil)
	default:
		endpoint = mieruprotocol.NewUnderlayProperties(mtu, mierucommon.StreamTransport, &gonet.TCPAddr{IP: listenIP, Port: int(port)}, nil)
	}

	// mieru validates a nil pattern into its default rather than rejecting it.
	pattern, err := trafficpattern.NewConfig(nil)
	if err != nil {
		return nil, errors.New("failed to build mieru traffic pattern").Base(err)
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	sockopt := &socketListener{ctx: listenerCtx}
	if streamSettings != nil {
		sockopt.settings = streamSettings.SocketSettings
	}

	mux := mieruprotocol.NewMux(false)
	mux.SetStreamListenerFactory(sockopt).
		SetPacketListenerFactory(sockopt).
		SetTrafficPattern(pattern).
		SetServerUsers(toMieruUsers(manager.MieruUsers())).
		SetServerUserHintIsMandatory(false).
		SetEndpoints([]mieruprotocol.UnderlayProperties{endpoint})

	if err := mux.Start(); err != nil {
		cancel()
		return nil, errors.New("failed to start mieru server").Base(err)
	}

	listener := &Listener{
		mux:     mux,
		manager: manager,
		addr:    endpoint.LocalAddr(),
		cancel:  cancel,
	}

	// This is what makes a panel-driven add or remove take effect without
	// restarting the inbound: Mux accepts a new user map while it is running, and
	// existing sessions keep their already-derived keys.
	manager.SetMieruUserObserver(func(users []User) {
		mux.SetServerUsers(toMieruUsers(users))
	})

	go listener.acceptLoop(listenerCtx, handler)

	errors.LogInfo(ctx, "mieru server listening on ", address, ":", port, " over ", transport.String())

	return listener, nil
}

func (l *Listener) acceptLoop(ctx context.Context, handler internet.ConnHandler) {
	for {
		conn, err := l.mux.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			errors.LogInfoInner(ctx, err, "failed to accept mieru connection")
			// Mux.Accept only fails for good once the Mux is closed, and that path
			// is covered above; a transient error here means one client, not the
			// listener, so keep serving.
			continue
		}
		if conn == nil {
			continue
		}
		select {
		case <-ctx.Done():
			conn.Close()
			return
		default:
		}
		handler(stat.Connection(conn))
	}
}

// toMieruUsers converts the inbound's users into the map Mux keys on.
//
// Passwords stay in plaintext on purpose. mieru hashes them per connection, with
// the user name as the salt, at the point the session key is derived; handing it
// an already-hashed password would derive a different key than the client's.
func toMieruUsers(users []User) map[string]*appctlpb.User {
	result := make(map[string]*appctlpb.User, len(users))
	for _, user := range users {
		if user.Name == "" {
			continue
		}
		result[user.Name] = &appctlpb.User{
			Name:     proto.String(user.Name),
			Password: proto.String(user.Password),
		}
	}
	return result
}

// socketListener lets mieru bind through Xray's own listener stack, so an
// inbound's `sockopt` (mark, bind-to-device, TCP fast open, ...) applies to the
// mieru underlay the same way it would to any other transport.
type socketListener struct {
	ctx      context.Context
	settings *internet.SocketConfig
}

var (
	_ apicommon.StreamListenerFactory = (*socketListener)(nil)
	_ apicommon.PacketListenerFactory = (*socketListener)(nil)
)

func (l *socketListener) Listen(ctx context.Context, network, address string) (gonet.Listener, error) {
	addr, err := gonet.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return internet.ListenSystem(l.contextOr(ctx), addr, l.settings)
}

func (l *socketListener) ListenPacket(ctx context.Context, network, address string) (gonet.PacketConn, error) {
	addr, err := gonet.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return internet.ListenSystemPacket(l.contextOr(ctx), addr, l.settings)
}

// contextOr prefers the listener's context. mieru passes context.Background()
// here, which would drop the inbound tag and session data that ListenSystem's
// hooks read.
func (l *socketListener) contextOr(ctx context.Context) context.Context {
	if l.ctx != nil {
		return l.ctx
	}
	return ctx
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
