package tuic

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ClientSettings carries the outbound side of a TUIC configuration. The
// credentials live in the proxy config (`proxy/tuic`), while the QUIC
// connection is owned by this transport, so the proxy hands them over here.
type ClientSettings struct {
	UUID              [16]byte
	Password          string
	CongestionControl string
	UDPStream         bool
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
}

// Client owns a single multiplexed QUIC connection to one TUIC server. Every
// request of the owning outbound reuses it; the connection is re-dialed lazily
// whenever the previous one died.
type Client struct {
	settings ClientSettings

	access  sync.Mutex
	conn    *quic.Conn
	tr      *quic.Transport
	pktConn stdnet.PacketConn
	connCtx context.Context
	cancel  context.CancelFunc

	udpAccess  sync.RWMutex
	udpConnMap map[uint16]*udpPacketConn
	sessionID  atomic.Uint32
}

func NewClient(settings ClientSettings) (*Client, error) {
	switch settings.CongestionControl {
	case "":
		settings.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, errors.New("unknown congestion control algorithm: ", settings.CongestionControl)
	}
	if settings.Heartbeat <= 0 {
		settings.Heartbeat = 10 * time.Second
	}
	return &Client{
		settings:   settings,
		udpConnMap: make(map[uint16]*udpPacketConn),
	}, nil
}

// Dial returns either a TUIC relay stream (TCP) or a TUIC UDP session,
// depending on UDPFromContext.
func (c *Client) Dial(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	quicConn, connCtx, err := c.connection(ctx, dest, streamSettings)
	if err != nil {
		return nil, err
	}
	if UDPFromContext(ctx) {
		return c.openUDPSession(connCtx, quicConn), nil
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		c.closeConnection(quicConn)
		return nil, errors.New("failed to open TUIC stream").Base(err)
	}
	return &streamConn{
		Stream: stream,
		local:  quicConn.LocalAddr(),
		remote: quicConn.RemoteAddr(),
	}, nil
}

func (c *Client) connection(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) (*quic.Conn, context.Context, error) {
	c.access.Lock()
	defer c.access.Unlock()

	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.closeLocked()
		default:
			return c.conn, c.connCtx, nil
		}
	}

	if err := c.dialLocked(ctx, dest, streamSettings); err != nil {
		c.closeLocked()
		return nil, nil, err
	}
	return c.conn, c.connCtx, nil
}

func (c *Client) dialLocked(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) error {
	tlsConfig, err := GetTLSConfigFromStreamSettings(streamSettings, dest)
	if err != nil {
		return err
	}

	udpDest := xnet.UDPDestination(dest.Address, dest.Port)
	rawConn, err := internet.DialSystem(ctx, udpDest, streamSettings.SocketSettings)
	if err != nil {
		return errors.New("failed to dial to TUIC server").Base(err)
	}

	var pktConn stdnet.PacketConn
	var serverAddr stdnet.Addr
	switch typed := rawConn.(type) {
	case *internet.PacketConnWrapper:
		pktConn = typed.PacketConn
		serverAddr = rawConn.RemoteAddr()
	case *cnc.Connection:
		pktConn = &internet.FakePacketConn{Conn: typed}
		tcpAddr, ok := typed.RemoteAddr().(*stdnet.TCPAddr)
		if !ok {
			_ = rawConn.Close()
			return errors.New("unexpected TUIC remote address ", typed.RemoteAddr())
		}
		serverAddr = &stdnet.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}
	default:
		_ = rawConn.Close()
		return errors.New("TUIC requires a packet connection")
	}

	if streamSettings.UdpmaskManager != nil {
		maskedConn, err := streamSettings.UdpmaskManager.WrapPacketConnClient(pktConn)
		if err != nil {
			_ = pktConn.Close()
			return errors.New("mask err").Base(err)
		}
		pktConn = maskedConn
	}

	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           1200,
		AssumePeerMaxDatagramFrameSize: 1200,
		MaxIncomingStreams:             1 << 60,
		MaxIncomingUniStreams:          1 << 60,
		KeepAlivePeriod:                c.settings.Heartbeat,
		DisablePathManager:             true,
	}

	tr := &quic.Transport{Conn: pktConn}
	var quicConn *quic.Conn
	if c.settings.ZeroRTTHandshake {
		quicConn, err = tr.DialEarly(ctx, serverAddr, tlsConfig, quicConfig)
	} else {
		quicConn, err = tr.Dial(ctx, serverAddr, tlsConfig, quicConfig)
	}
	if err != nil {
		_ = tr.Close()
		_ = pktConn.Close()
		return errors.New("failed to handshake with TUIC server").Base(err)
	}

	if c.settings.CongestionControl == "bbr" {
		congestion.UseBBR(quicConn, bbr.ProfileStandard)
	}

	connCtx, cancel := context.WithCancel(context.Background())
	c.conn = quicConn
	c.tr = tr
	c.pktConn = pktConn
	c.connCtx = connCtx
	c.cancel = cancel

	if c.settings.ZeroRTTHandshake {
		// 0-RTT hands out a usable connection before the handshake finishes, but
		// the authentication token is derived from exported keying material, so
		// it has to wait. The server queues pre-auth commands for us.
		go func() {
			select {
			case <-quicConn.HandshakeComplete():
			case <-connCtx.Done():
				return
			}
			if err := c.authenticate(quicConn); err != nil {
				errors.LogWarning(connCtx, "TUIC authentication failed: ", err)
				c.closeConnection(quicConn)
			}
		}()
	} else if err := c.authenticate(quicConn); err != nil {
		return errors.New("failed to authenticate to TUIC server").Base(err)
	}

	go c.loopUniStreams(connCtx, quicConn)
	go c.loopMessages(connCtx, quicConn)
	go c.loopHeartbeat(connCtx, quicConn)

	errors.LogInfo(ctx, "TUIC connected to ", quicConn.RemoteAddr())
	return nil
}

func (c *Client) authenticate(quicConn *quic.Conn) error {
	tlsState := quicConn.ConnectionState().TLS
	token, err := tlsState.ExportKeyingMaterial(string(c.settings.UUID[:]), []byte(c.settings.Password), 32)
	if err != nil {
		return errors.New("failed to export TUIC keying material").Base(err)
	}
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buffer := bytes.NewBuffer(make([]byte, 0, authenticateLen))
	buffer.WriteByte(tuicVersion)
	buffer.WriteByte(commandAuthenticate)
	buffer.Write(c.settings.UUID[:])
	buffer.Write(token)
	if _, err := stream.Write(buffer.Bytes()); err != nil {
		_ = stream.Close()
		return err
	}
	return stream.Close()
}

func (c *Client) loopUniStreams(ctx context.Context, quicConn *quic.Conn) {
	for {
		stream, err := quicConn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		go func() {
			defer stream.CancelRead(0)
			if err := c.handleUniStream(stream); err != nil {
				errors.LogDebug(ctx, "TUIC uni-stream error: ", err)
			}
		}()
	}
}

func (c *Client) handleUniStream(stream *quic.ReceiveStream) error {
	var header [2]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return err
	}
	if header[0] != tuicVersion {
		return errors.New("unknown version ", header[0])
	}
	if header[1] != commandPacket {
		return errors.New("unexpected command ", header[1])
	}
	message := new(udpMessage)
	if err := readUDPMessage(message, stream); err != nil {
		return err
	}
	c.handleUDPMessage(message)
	return nil
}

func (c *Client) loopMessages(ctx context.Context, quicConn *quic.Conn) {
	for {
		data, err := quicConn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(data) < 2 || data[0] != tuicVersion {
			continue
		}
		switch data[1] {
		case commandPacket:
			message := new(udpMessage)
			if err := decodeUDPMessage(message, data[2:]); err != nil {
				errors.LogDebug(ctx, "TUIC failed to decode datagram: ", err)
				continue
			}
			c.handleUDPMessage(message)
		case commandHeartbeat:
		default:
			errors.LogDebug(ctx, "TUIC unknown datagram command ", data[1])
		}
	}
}

// loopHeartbeat keeps the UDP relay sessions alive on the server. TUIC only
// requires it while at least one session exists, so an idle TCP-only
// connection stays silent (QUIC keep-alive still covers the connection).
func (c *Client) loopHeartbeat(ctx context.Context, quicConn *quic.Conn) {
	ticker := time.NewTicker(c.settings.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-quicConn.Context().Done():
			return
		case <-ticker.C:
		}
		c.udpAccess.RLock()
		idle := len(c.udpConnMap) == 0
		c.udpAccess.RUnlock()
		if idle {
			continue
		}
		if err := quicConn.SendDatagram([]byte{tuicVersion, commandHeartbeat}); err != nil {
			errors.LogDebug(ctx, "TUIC heartbeat failed: ", err)
		}
	}
}

func (c *Client) handleUDPMessage(message *udpMessage) {
	c.udpAccess.RLock()
	udpConn := c.udpConnMap[message.sessionID]
	c.udpAccess.RUnlock()
	if udpConn == nil || udpConn.done() {
		return
	}
	udpConn.inputPacket(message)
}

func (c *Client) openUDPSession(ctx context.Context, quicConn *quic.Conn) *udpPacketConn {
	sessionID := uint16(c.sessionID.Add(1))
	udpConn := newUDPPacketConn(ctx, quicConn, c.settings.UDPStream, false, nil, func() {
		c.udpAccess.Lock()
		delete(c.udpConnMap, sessionID)
		c.udpAccess.Unlock()
	})
	udpConn.sessionID = sessionID
	c.udpAccess.Lock()
	if previous := c.udpConnMap[sessionID]; previous != nil {
		previous.closeWithError(io.ErrClosedPipe)
	}
	c.udpConnMap[sessionID] = udpConn
	c.udpAccess.Unlock()
	return udpConn
}

// closeConnection tears the shared connection down, but only if it is still the
// current one — a concurrent request may already have re-dialed.
func (c *Client) closeConnection(quicConn *quic.Conn) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != quicConn {
		return
	}
	c.closeLocked()
}

func (c *Client) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	c.closeLocked()
	return nil
}

func (c *Client) closeLocked() {
	var errs []error
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.conn != nil {
		errs = append(errs, c.conn.CloseWithError(0, ""))
		c.conn = nil
	}
	if c.tr != nil {
		errs = append(errs, c.tr.Close())
		c.tr = nil
	}
	if c.pktConn != nil {
		errs = append(errs, c.pktConn.Close())
		c.pktConn = nil
	}
	c.connCtx = nil

	c.udpAccess.Lock()
	udpConns := c.udpConnMap
	c.udpConnMap = make(map[uint16]*udpPacketConn)
	c.udpAccess.Unlock()
	for _, udpConn := range udpConns {
		udpConn.cancel(io.ErrClosedPipe)
	}

	if err := stderrors.Join(errs...); err != nil {
		errors.LogDebug(context.Background(), "TUIC connection close: ", err)
	}
}

// WriteConnectHeader writes the `Connect` command of a TUIC relay stream. The
// proxy owns it because only the proxy knows the request destination.
func WriteConnectHeader(writer io.Writer, destination xnet.Destination) error {
	if _, err := writer.Write([]byte{tuicVersion, commandConnect}); err != nil {
		return err
	}
	return writeDestination(writer, destination)
}
