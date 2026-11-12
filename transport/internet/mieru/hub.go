package mieru

import (
	"context"
	stderrors "errors"
	"io"
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

type Listener struct {
	mux     *mieruprotocol.Mux
	manager UserManager
	addr    net.Addr
	cancel  context.CancelFunc
	sockets *socketListener

	closeOnce sync.Once
}

func (l *Listener) Addr() gonet.Addr {
	return l.addr
}

func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.cancel()
		// Detach first: the inbound outlives the listener when only stream settings change.
		if l.manager != nil {
			l.manager.SetMieruUserObserver(nil)
		}
		// Mux.Close waits ~1s per session before freeing the port: free it and drop conns now.
		err = l.sockets.closeAll()
		go l.mux.Close()
	})
	return err
}

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

	// Not PortBindingsToUnderlayProperties, which hardcodes 0.0.0.0 and ignores `listen`.
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
		sockets: sockopt,
	}

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
			// Accept only fails for good after Close; here one client failed.
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

// Plaintext on purpose: mieru hashes it with the user name when deriving the key.
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

type socketListener struct {
	ctx      context.Context
	settings *internet.SocketConfig

	mu    sync.Mutex
	open  []io.Closer
	conns sync.Map // *ingressConn -> struct{}
}

func (l *socketListener) track(c io.Closer) {
	l.mu.Lock()
	l.open = append(l.open, c)
	l.mu.Unlock()
}

func (l *socketListener) closeAll() error {
	l.mu.Lock()
	open := l.open
	l.open = nil
	l.mu.Unlock()
	var errs []error
	for _, c := range open {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	l.conns.Range(func(k, _ interface{}) bool {
		k.(*ingressConn).Close()
		return true
	})
	return stderrors.Join(errs...)
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
	listener, err := internet.ListenSystem(l.contextOr(ctx), addr, l.settings)
	if err != nil {
		return nil, err
	}
	l.track(listener)
	return &ingressListener{Listener: listener, conns: &l.conns}, nil
}

func (l *socketListener) ListenPacket(ctx context.Context, network, address string) (gonet.PacketConn, error) {
	addr, err := gonet.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn, err := internet.ListenSystemPacket(l.contextOr(ctx), addr, l.settings)
	if err != nil {
		return nil, err
	}
	l.track(conn)
	return conn, nil
}

// mieru passes context.Background(), which drops what ListenSystem's hooks read.
func (l *socketListener) contextOr(ctx context.Context) context.Context {
	if l.ctx != nil {
		return l.ctx
	}
	return ctx
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
