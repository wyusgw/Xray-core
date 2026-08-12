package mieru

import (
	"bytes"
	"context"
	gonet "net"
	"strings"
	"sync"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	mierutransport "github.com/xtls/xray-core/transport/internet/mieru"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// handshakeTimeout bounds the wait for the socks5 request that follows a mieru
// handshake, matching what mieru's own server allows.
const handshakeTimeout = 10 * time.Second

// Inbound is the mieru server.
//
// The authentication and the crypto live in transport/internet/mieru, because
// mieru binds its own sockets and hands back streams that are already decrypted
// and already attributed to a user. What is left here is the socks5 request that
// rides the stream — the same split mieru's own apis/server draws between
// Mux.Accept and Server.Accept.
type Inbound struct {
	config *ServerConfig

	// Two indexes over the same users: the handler service keys on email, mieru
	// keys on user name. Both are needed, so both are kept.
	mu       sync.RWMutex
	byEmail  map[string]*protocol.MemoryUser
	byName   map[string]*protocol.MemoryUser
	observer func([]mierutransport.User)
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	inbound := &Inbound{
		config:  config,
		byEmail: make(map[string]*protocol.MemoryUser),
		byName:  make(map[string]*protocol.MemoryUser),
	}
	for _, user := range config.GetUsers() {
		memUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to parse mieru user").Base(err).AtError()
		}
		if err := inbound.addUser(memUser); err != nil {
			return nil, err
		}
	}
	return inbound, nil
}

func (i *Inbound) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// MieruInboundUserManager hands the listener the live user set. It is called
// from app/proxyman/inbound/worker.go before the transport starts listening.
func (i *Inbound) MieruInboundUserManager() mierutransport.UserManager {
	return i
}

// MieruInboundSettings are the protocol settings the listener needs.
func (i *Inbound) MieruInboundSettings() mierutransport.ServerSettings {
	return mierutransport.ServerSettings{
		Transport: i.config.GetTransport(),
		MTU:       i.config.GetMtu(),
	}
}

func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.Name = protocolName
	inbound.CanSpliceCopy = 3

	// The request has to be read before the user can be recovered. On the stream
	// underlay mieru only attaches the user name to the session once it has
	// decrypted a segment, so asking any earlier gets an empty name even though
	// the handshake did authenticate — which is why mieru's own apis/server does
	// the same read inside Accept before handing the connection over.
	request, err := readRequest(connection)
	if err != nil {
		return errors.New("failed to read mieru socks5 request").Base(err)
	}

	// Recovering which user it was is what makes the traffic countable against
	// them. The connection is already authenticated by this point: it decrypted,
	// so it matched a registered password.
	conn := stat.TryUnwrapStatsConn(connection)
	if named, ok := conn.(apicommon.UserContext); ok {
		if user := i.userByName(named.UserName()); user != nil {
			inbound.User = user
		}
	}
	if inbound.User == nil {
		return errors.New("mieru connection carries no known user")
	}

	switch request.Command {
	case constant.Socks5ConnectCmd:
		destination := toDestination(request.DstAddr, net.Network_TCP)
		if !destination.IsValid() {
			writeReply(connection, constant.Socks5ReplyAddrTypeNotSupported)
			return errors.New("invalid mieru TCP destination")
		}
		return i.processTCP(ctx, connection, destination, dispatcher)
	case constant.Socks5UDPAssociateCmd:
		destination := toDestination(request.DstAddr, net.Network_UDP)
		if !destination.IsValid() {
			writeReply(connection, constant.Socks5ReplyAddrTypeNotSupported)
			return errors.New("invalid mieru UDP destination")
		}
		return i.processUDP(ctx, connection, destination, dispatcher)
	default:
		writeReply(connection, constant.Socks5ReplyCommandNotSupported)
		return errors.New("unsupported mieru socks5 command ", request.Command)
	}
}

func (i *Inbound) processTCP(ctx context.Context, conn stat.Connection, destination net.Destination, dispatcher routing.Dispatcher) error {
	// mieru's client waits for this reply before it sends payload unless the
	// profile asked for a 0-RTT handshake, and even then it reads one. Xray only
	// learns whether the destination is reachable after the dispatcher has run,
	// so report success here the way a socks5 proxy with a deferred dial does.
	if err := writeReply(conn, constant.Socks5ReplySuccess); err != nil {
		return errors.New("failed to write mieru socks5 response").Base(err)
	}

	ctx = withAccessMessage(ctx, conn, destination)
	errors.LogInfo(ctx, "tunneling mieru request to tcp:", destination)

	return dispatcher.DispatchLink(ctx, destination, &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(conn),
	})
}

func (i *Inbound) processUDP(ctx context.Context, conn stat.Connection, destination net.Destination, dispatcher routing.Dispatcher) error {
	if err := writeReply(conn, constant.Socks5ReplySuccess); err != nil {
		return errors.New("failed to write mieru socks5 response").Base(err)
	}

	ctx = withAccessMessage(ctx, conn, destination)
	errors.LogInfo(ctx, "tunneling mieru request to udp:", destination)

	// The packets keep their boundaries inside the stream, and each one carries
	// its own destination in a socks5 UDP-associate header — the mirror of what
	// the outbound in client.go builds.
	tunnel := apicommon.NewPacketOverStreamTunnel(conn)
	return dispatcher.DispatchLink(ctx, destination, &transport.Link{
		Reader: &serverUDPPacketReader{tunnel: tunnel, destination: destination},
		Writer: &serverUDPPacketWriter{tunnel: tunnel, destination: destination},
	})
}

// readRequest reads the socks5 request that follows the mieru handshake.
func readRequest(conn stat.Connection) (*model.Request, error) {
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err == nil {
		defer conn.SetReadDeadline(time.Time{})
	}
	request := &model.Request{}
	if err := request.ReadFromSocks5(conn); err != nil {
		return nil, err
	}
	return request, nil
}

// writeReply answers the socks5 request. The bind address is always zero: the
// dispatcher picks the outgoing socket, and mieru's client ignores the field for
// a CONNECT and rewrites the port for an associate.
func writeReply(conn stat.Connection, reply byte) error {
	return model.WriteSocks5Response(conn, reply, model.AddrSpec{IP: gonet.IPv4zero, Port: 0})
}

func withAccessMessage(ctx context.Context, conn stat.Connection, destination net.Destination) context.Context {
	email := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		email = inbound.User.Email
	}
	return log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Email:  email,
	})
}

// toDestination converts a socks5 address, leaving a domain name unresolved so
// routing and DNS rules see it.
func toDestination(addr model.AddrSpec, network net.Network) net.Destination {
	port := net.Port(addr.Port)
	if addr.FQDN != "" {
		return net.Destination{Network: network, Address: net.DomainAddress(addr.FQDN), Port: port}
	}
	if len(addr.IP) == 0 {
		return net.Destination{}
	}
	return net.Destination{Network: network, Address: net.IPAddress(addr.IP), Port: port}
}

// serverUDPPacketReader turns the client's socks5 UDP datagrams into buffers tagged
// with the destination each one asked for.
type serverUDPPacketReader struct {
	tunnel      *apicommon.PacketOverStreamTunnel
	destination net.Destination
}

func (r *serverUDPPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	// A datagram carries its header inline, so the read has to be able to hold a
	// maximum-size packet plus that header rather than a single buf.Buffer.
	scratch := make([]byte, 65535)
	n, err := r.tunnel.Read(scratch)
	if err != nil {
		return nil, err
	}
	if n < 3 {
		return nil, errors.New("mieru UDP datagram is too short to hold a header")
	}
	if scratch[0] != 0x00 || scratch[1] != 0x00 {
		return nil, errors.New("invalid mieru UDP associate header")
	}
	if scratch[2] != 0x00 {
		return nil, errors.New("mieru UDP fragments are not supported")
	}

	var addr model.NetAddrSpec
	reader := bytes.NewReader(scratch[3:n])
	if err := addr.ReadFromSocks5(reader); err != nil {
		return nil, errors.New("failed to read mieru UDP destination").Base(err)
	}
	destination := toDestination(addr.AddrSpec, net.Network_UDP)
	if !destination.IsValid() {
		destination = r.destination
	}

	payload := make([]byte, reader.Len())
	if _, err := reader.Read(payload); err != nil && len(payload) > 0 {
		return nil, err
	}

	buffer := buf.NewWithSize(int32(len(payload)))
	if _, err := buffer.Write(payload); err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.UDP = &destination
	return buf.MultiBuffer{buffer}, nil
}

// serverUDPPacketWriter sends replies back with the origin of each packet in its
// header, which is how the client tells apart answers from different peers.
type serverUDPPacketWriter struct {
	tunnel      *apicommon.PacketOverStreamTunnel
	destination net.Destination
}

func (w *serverUDPPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, buffer := range mb {
		source := w.destination
		if buffer.UDP != nil {
			source = *buffer.UDP
		}
		if !source.IsValid() {
			buffer.Release()
			continue
		}
		var addr model.NetAddrSpec
		addr.Net = "udp"
		addr.Port = int(source.Port.Value())
		if source.Address.Family().IsDomain() {
			addr.FQDN = source.Address.Domain()
		} else {
			addr.IP = source.Address.IP()
		}

		packet := bytes.NewBuffer([]byte{0x00, 0x00, 0x00})
		if err := addr.WriteToSocks5(packet); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		packet.Write(buffer.Bytes())
		if _, err := w.tunnel.Write(packet.Bytes()); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		buffer.Release()
	}
	return nil
}

func (w *serverUDPPacketWriter) Close() error {
	return w.tunnel.Close()
}

// MieruUsers implements transport/internet/mieru.UserManager.
func (i *Inbound) MieruUsers() []mierutransport.User {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.mieruUsersLocked()
}

func (i *Inbound) mieruUsersLocked() []mierutransport.User {
	users := make([]mierutransport.User, 0, len(i.byName))
	for name, user := range i.byName {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		users = append(users, mierutransport.User{Name: name, Password: account.Password})
	}
	return users
}

// SetMieruUserObserver implements transport/internet/mieru.UserManager.
func (i *Inbound) SetMieruUserObserver(observer func([]mierutransport.User)) {
	i.mu.Lock()
	i.observer = observer
	users := i.mieruUsersLocked()
	i.mu.Unlock()

	// Push the current set straight away: the listener may have been rebuilt
	// while users were being added, and this is cheaper than making it ask.
	if observer != nil {
		observer(users)
	}
}

// notify hands the listener the new user set. It must be called without the
// lock held, because the listener re-enters mieru while it applies them.
func (i *Inbound) notify() {
	i.mu.RLock()
	observer := i.observer
	users := i.mieruUsersLocked()
	i.mu.RUnlock()
	if observer != nil {
		observer(users)
	}
}

func (i *Inbound) userByName(name string) *protocol.MemoryUser {
	if name == "" {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.byName[name]
}

// addUser indexes a user under both keys. The caller holds no lock on the first
// call from NewServer, which is safe because nothing else can see the inbound
// yet; AddUser below takes the lock itself.
func (i *Inbound) addUser(user *protocol.MemoryUser) error {
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("invalid mieru account type")
	}
	if account.Username == "" {
		return errors.New("mieru user name must not be empty")
	}
	i.byName[account.Username] = user
	if user.Email != "" {
		i.byEmail[strings.ToLower(user.Email)] = user
	}
	return nil
}

// AddUser implements proxy.UserManager. A user added here can connect
// immediately: the listener is handed the new set without being restarted.
func (i *Inbound) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("invalid mieru account type")
	}
	if account.Username == "" {
		return errors.New("mieru user name must not be empty")
	}

	i.mu.Lock()
	email := strings.ToLower(user.Email)
	if email != "" {
		if _, found := i.byEmail[email]; found {
			i.mu.Unlock()
			return errors.New("user ", user.Email, " already exists")
		}
		i.byEmail[email] = user
	}
	i.byName[account.Username] = user
	i.mu.Unlock()

	i.notify()
	return nil
}

// RemoveUser implements proxy.UserManager. Existing sessions of a removed user
// are left alone — mieru derives their keys at handshake time — but no new
// session can be opened.
func (i *Inbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("email must not be empty")
	}
	lower := strings.ToLower(email)

	i.mu.Lock()
	user, found := i.byEmail[lower]
	if !found {
		i.mu.Unlock()
		return errors.New("user ", email, " not found")
	}
	delete(i.byEmail, lower)
	if account, ok := user.Account.(*MemoryAccount); ok {
		delete(i.byName, account.Username)
	}
	i.mu.Unlock()

	i.notify()
	return nil
}

func (i *Inbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.byEmail[strings.ToLower(email)]
}

func (i *Inbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	i.mu.RLock()
	defer i.mu.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(i.byName))
	for _, user := range i.byName {
		users = append(users, user)
	}
	return users
}

func (i *Inbound) GetUsersCount(ctx context.Context) int64 {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return int64(len(i.byName))
}
