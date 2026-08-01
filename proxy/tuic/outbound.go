package tuic

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	tuictransport "github.com/xtls/xray-core/transport/internet/tuic"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutbound(ctx, config.(*ClientConfig))
	}))
}

// Outbound is the TUIC outbound handler
type Outbound struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	client        *tuictransport.Client
}

// NewOutbound creates a new TUIC outbound handler
func NewOutbound(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config == nil {
		return nil, newError("TUIC outbound config is nil")
	}
	if len(config.Server) == 0 {
		return nil, newError("no server specified")
	}

	streamSettings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if !ok || streamSettings == nil {
		return nil, newError(`TUIC outbound requires "streamSettings": {"network": "tuic", "security": "tls"}`)
	}
	if _, ok := streamSettings.ProtocolSettings.(*tuictransport.Config); !ok {
		return nil, newError(`TUIC outbound requires "network": "tuic", got: `, streamSettings.ProtocolName)
	}

	server, err := protocol.NewServerSpecFromPB(config.Server[0])
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, newError("TUIC outbound user is not specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, newError("TUIC outbound has an invalid account type")
	}

	client, err := tuictransport.NewClient(tuictransport.ClientSettings{
		UUID:              account.UUID,
		Password:          account.Password,
		CongestionControl: config.GetCongestionControl(),
		UDPStream:         config.GetUdpStream(),
		ZeroRTTHandshake:  config.GetZeroRttHandshake(),
		Heartbeat:         seconds(config.GetHeartbeat()),
	})
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	return &Outbound{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		client:        client,
	}, nil
}

// Process processes an outbound connection
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return newError("invalid outbound target")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return newError("target not specified")
	}
	ob.Name = "tuic"
	ob.CanSpliceCopy = 3
	target := ob.Target

	dialCtx := tuictransport.ContextWithClient(ctx, o.client)
	dialCtx = tuictransport.ContextWithUDP(dialCtx, target.Network == net.Network_UDP)
	conn, err := dialer.Dial(dialCtx, o.server.Destination)
	if err != nil {
		return errors.New("failed to find an available destination").AtWarning().Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", target.Network, ":", o.server.Destination.NetAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := o.policyManager.ForLevel(o.server.User.Level)
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

	switch target.Network {
	case net.Network_TCP:
		return o.processTCP(ctx, link, conn, target, sessionPolicy, timer)
	case net.Network_UDP:
		return o.processUDP(ctx, link, conn, target, sessionPolicy, timer)
	default:
		return newError("unsupported network ", target.Network)
	}
}

func (o *Outbound) processTCP(ctx context.Context, link *transport.Link, conn stat.Connection, target net.Destination, sessionPolicy policy.Session, timer *signal.ActivityTimer) error {
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := tuictransport.WriteConnectHeader(bufferedWriter, target); err != nil {
			return errors.New("failed to write request").Base(err)
		}
		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}
		return buf.Copy(link.Reader, bufferedWriter, buf.UpdateActivity(timer))
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

func (o *Outbound) processUDP(ctx context.Context, link *transport.Link, conn stat.Connection, target net.Destination, sessionPolicy policy.Session, timer *signal.ActivityTimer) error {
	packetConn, ok := stat.TryUnwrapStatsConn(conn).(tuictransport.PacketConn)
	if !ok {
		return newError("udp requires the tuic udp transport")
	}

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
		reader := &udpPacketReader{conn: packetConn}
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

// Close releases the shared QUIC connection when the outbound handler is
// removed (config reload / API call).
func (o *Outbound) Close() error {
	if o.client == nil {
		return nil
	}
	return o.client.Close()
}
