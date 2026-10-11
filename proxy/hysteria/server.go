package hysteria

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/hysteria2/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	hysteriatransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Server is the first-generation inbound. The `hysteria` transport listens and
// authenticates; it hands this server one connection per request.
type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	streamSettings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if !ok || streamSettings == nil {
		return nil, errors.New("not hysteria transport")
	}
	if _, ok := streamSettings.ProtocolSettings.(*hysteriatransport.Config); !ok {
		return nil, errors.New("not hysteria transport")
	}

	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get hysteria user").Base(err)
		}
		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err)
		}
	}

	return &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (s *Server) HysteriaInboundValidator() *account.Validator {
	return s.validator
}

func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return s.validator.Add(user)
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	return s.validator.DelByEmail(email)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.Process.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = protocolName
	inbound.CanSpliceCopy = 3
	inbound.User = &protocol.MemoryUser{}

	iConn := stat.TryUnwrapStatsConn(conn)
	if v, ok := iConn.(interface{ User() *protocol.MemoryUser }); ok {
		if user := v.User(); user != nil {
			inbound.User = user
		}
	}

	switch c := iConn.(type) {
	case *hysteriatransport.UDPConn:
		return s.processUDP(ctx, c, dispatcher)
	case *hysteriatransport.StreamConn:
		return s.processTCP(ctx, c, conn, inbound.User, dispatcher)
	}
	return errors.New("unexpected connection ", conn.RemoteAddr())
}

func (s *Server) processTCP(ctx context.Context, c *hysteriatransport.StreamConn, conn stat.Connection, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	host, port := c.Target()
	dest, err := net.ParseDestination("tcp:" + net.JoinHostPort(host, portText(port)))
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		return errors.New("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to ", dest)

	bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := hysteriatransport.WriteResponse(bufferedWriter, true, 0, "Connected"); err != nil {
		return errors.New("failed to write response").Base(err)
	}
	if err := bufferedWriter.SetBuffered(false); err != nil {
		return err
	}

	return dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: bufferedWriter,
	})
}

func (s *Server) processUDP(ctx context.Context, c *hysteriatransport.UDPConn, dispatcher routing.Dispatcher) error {
	readCtx, cancel := context.WithTimeout(ctx, s.policyManager.ForLevel(0).Timeouts.Handshake+10*time.Second)
	host, port, data, err := c.ReadPacket(readCtx)
	cancel()
	if err != nil {
		return err
	}
	dest, err := net.ParseDestination("udp:" + net.JoinHostPort(host, portText(port)))
	if err != nil {
		return err
	}
	first := buf.New()
	_, _ = first.Write(data)
	first.UDP = &dest

	return dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: &serverUDPReader{ctx: ctx, conn: c, first: first},
		Writer: &serverUDPWriter{conn: c, host: host, port: port},
	})
}

type serverUDPReader struct {
	ctx   context.Context
	conn  *hysteriatransport.UDPConn
	first *buf.Buffer
}

func (r *serverUDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.first != nil {
		b := r.first
		r.first = nil
		return buf.MultiBuffer{b}, nil
	}
	for {
		host, port, data, err := r.conn.ReadPacket(r.ctx)
		if err != nil {
			return nil, err
		}
		dest, err := net.ParseDestination("udp:" + net.JoinHostPort(host, portText(port)))
		if err != nil || len(data) > buf.Size {
			continue
		}
		b := buf.New()
		_, _ = b.Write(data)
		b.UDP = &dest
		return buf.MultiBuffer{b}, nil
	}
}

type serverUDPWriter struct {
	conn *hysteriatransport.UDPConn
	host string
	port uint16
}

func (w *serverUDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		host, port := w.host, w.port
		if b.UDP != nil {
			host, port = b.UDP.Address.String(), uint16(b.UDP.Port)
		}
		if err := w.conn.WritePacket(host, port, b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
