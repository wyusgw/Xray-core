package hysteria

import (
	"context"
	"crypto/rand"
	"runtime"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria2/account"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type Listener struct {
	validator  *account.Validator
	quicParams *internet.QuicParams
	addConn    internet.ConnHandler

	pktConn  net.PacketConn
	tr       *quic.Transport
	listener *quic.Listener
}

// handleClient runs one client's QUIC connection: the hello on its first
// stream, then a stream for each connection or UDP session.
func (l *Listener) handleClient(conn *quic.Conn) {
	ctx := context.Background()
	openCtx, cancel := context.WithTimeout(ctx, controlTimeout)
	control, err := conn.AcceptStream(openCtx)
	cancel()
	if err != nil {
		_ = conn.CloseWithError(closeCodeProtocol, "")
		return
	}
	_ = control.SetDeadline(time.Now().Add(controlTimeout))
	version, _, clientRecv, auth, err := readClientHello(control)
	if err != nil || version != protocolVersion {
		_ = conn.CloseWithError(closeCodeProtocol, "protocol error")
		return
	}

	user := l.validator.Get(auth)
	if user == nil {
		_ = writeServerHello(control, false, 0, 0, "Wrong password")
		time.Sleep(authFailDelay)
		_ = conn.CloseWithError(closeCodeAuth, "auth error")
		return
	}
	if err := writeServerHello(control, true, l.quicParams.BrutalUp, l.quicParams.BrutalDown, "Welcome"); err != nil {
		_ = conn.CloseWithError(closeCodeProtocol, "")
		return
	}
	_ = control.SetDeadline(time.Time{})
	l.useCongestion(conn, clientRecv)

	sessions := &udpSessions{m: map[uint32]*UDPConn{}}
	go sessions.run(conn)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go l.handleStream(conn, stream, sessions, user)
	}
}

// useCongestion sets the pace of the server's sending: the rate the client said
// it can receive at, held to the server's own limit.
func (l *Listener) useCongestion(conn *quic.Conn, clientRecv uint64) {
	p := l.quicParams
	rate := clientRecv
	if p.BrutalUp > 0 && (rate == 0 || p.BrutalUp < rate) {
		rate = p.BrutalUp
	}
	switch p.Congestion {
	case "reno":
	case "bbr":
		congestion.UseBBR(conn, bbr.Profile(p.BbrProfile))
	case "force-brutal":
		congestion.UseBrutal(conn, p.BrutalUp, p.BrutalDisableLossCompensation)
	default:
		if rate == 0 {
			congestion.UseBBR(conn, bbr.Profile(p.BbrProfile))
		} else {
			congestion.UseBrutal(conn, rate, p.BrutalDisableLossCompensation)
		}
	}
}

func (l *Listener) handleStream(conn *quic.Conn, stream *quic.Stream, sessions *udpSessions, user *protocol.MemoryUser) {
	_ = stream.SetReadDeadline(time.Now().Add(controlTimeout))
	udp, host, port, err := readRequest(stream)
	if err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if !udp {
		l.addConn(&StreamConn{
			stream: stream,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
			user:   user,
			host:   host,
			port:   port,
		})
		return
	}

	session := sessions.open(conn, stream, user)
	if err := WriteResponse(stream, true, session.id, "OK"); err != nil {
		_ = session.Close()
		return
	}
	l.addConn(session)

	// The session ends with the stream that opened it.
	var sink [64]byte
	for {
		if _, err := stream.Read(sink[:]); err != nil {
			_ = session.Close()
			return
		}
	}
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			if err != quic.ErrServerClosed {
				errors.LogErrorInner(context.Background(), err, "failed to serve hysteria")
			}
			break
		}
		go l.handleClient(conn)
	}
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) Close() error {
	return errors.Combine(l.listener.Close(), l.tr.Close(), l.pktConn.Close())
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("address is domain")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	validator := ValidatorFromContext(ctx)
	if validator == nil {
		return nil, errors.New("validator is nil")
	}
	config := streamSettings.ProtocolSettings.(*Config)

	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		MaxIncomingStreams:             quicParams.MaxIncomingStreams,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           maxDatagramFrame,
		AssumePeerMaxDatagramFrameSize: maxDatagramFrame,
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = streamWindow
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = streamWindow
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = connWindow
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = connWindow
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	if quicParams.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = 1024
	}

	var pktConn net.PacketConn
	var err error
	if streamSettings.FinalMask != nil {
		pktConn, err = streamSettings.FinalMask.ListenPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)})
	} else {
		pktConn, err = internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}
	if config.ObfsPassword != "" {
		pktConn = newXPlusConn(pktConn, config.ObfsPassword)
	}

	var k *quic.StatelessResetKey
	if !quicParams.DisableStatelessReset {
		k = &quic.StatelessResetKey{}
		common.Must2(rand.Read((*k)[:]))
	}

	tr := &quic.Transport{Conn: pktConn, DisableGSO: quicParams.DisableGSO, StatelessResetKey: k}

	listener, err := tr.Listen(tlsConfig.GetTLSConfig(tls.WithNextProto(defaultALPN)), quicConfig)
	if err != nil {
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, err
	}

	l := &Listener{
		validator:  validator,
		quicParams: quicParams,
		addConn:    handler,

		pktConn:  pktConn,
		tr:       tr,
		listener: listener,
	}

	go l.keepAccepting()

	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
