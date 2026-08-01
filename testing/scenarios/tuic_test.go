package scenarios

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/tuic"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

func newTUICUUID() string {
	id := uuid.New()
	return id.String()
}

func tuicLogConfig() []*serial.TypedMessage {
	return []*serial.TypedMessage{
		serial.ToTypedMessage(&log.Config{
			ErrorLogLevel: clog.Severity_Warning,
			ErrorLogType:  log.LogType_Console,
		}),
	}
}

// tuicStreamConfig is the "network": "tuic" transport both sides have to use;
// TUIC is a QUIC protocol, so TLS is mandatory rather than optional.
func tuicStreamConfig(securitySettings *serial.TypedMessage) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName:     "tuic",
		SecurityType:     serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{securitySettings},
	}
}

func tuicServerConfig(t *testing.T, serverPort net.Port, userUUID, password string, udpStream bool) (*core.Config, *core.Config, net.Port) {
	t.Helper()

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	serverConfig := &core.Config{
		App: tuicLogConfig(),
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:         net.NewIPOrDomain(net.LocalHostIP),
					StreamSettings: tuicStreamConfig(serial.ToTypedMessage(&tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(certificate)}})),
				}),
				ProxySettings: serial.ToTypedMessage(&tuic.ServerConfig{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&tuic.Account{
								Uuid:     userUUID,
								Password: password,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	clientConfig := &core.Config{
		App: tuicLogConfig(),
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&tuic.ClientConfig{
					Server: []*protocol.ServerEndpoint{
						{
							Address: net.NewIPOrDomain(net.LocalHostIP),
							Port:    uint32(serverPort),
							User: &protocol.User{
								Account: serial.ToTypedMessage(&tuic.Account{
									Uuid:     userUUID,
									Password: password,
								}),
							},
						},
					},
					UdpStream: udpStream,
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: tuicStreamConfig(serial.ToTypedMessage(&tls.Config{
						ServerName:           "localhost",
						PinnedPeerCertSha256: [][]byte{certificateHash[:]},
					})),
				}),
			},
		},
	}

	return serverConfig, clientConfig, serverPort
}

func TestTUICTCP(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverConfig, clientConfig, _ := tuicServerConfig(t, udp.PickPort(), newTUICUUID(), "tuic-password", false)

	clientPort := tcp.PickPort()
	clientConfig.Inbound = []*core.InboundHandlerConfig{
		{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var errGroup errgroup.Group
	for range 3 {
		// All three requests share one QUIC connection.
		errGroup.Go(testTCPConn(clientPort, 10240, time.Second*20))
	}
	if err := errGroup.Wait(); err != nil {
		t.Error(err)
	}
}

func TestTUICUDP(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		udpStream bool
	}{
		{name: "native", udpStream: false},
		{name: "quic", udpStream: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			udpServer := udp.Server{MsgProcessor: xor}
			udpDest, err := udpServer.Start()
			common.Must(err)
			defer udpServer.Close()

			serverConfig, clientConfig, _ := tuicServerConfig(t, udp.PickPort(), newTUICUUID(), "tuic-password", testCase.udpStream)

			clientPort := udp.PickPort()
			clientConfig.Inbound = []*core.InboundHandlerConfig{
				{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
					}),
					ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
						RewriteAddress:  net.NewIPOrDomain(udpDest.Address),
						RewritePort:     uint32(udpDest.Port),
						AllowedNetworks: []net.Network{net.Network_UDP},
					}),
				},
			}

			servers, err := InitializeServerConfigs(serverConfig, clientConfig)
			common.Must(err)
			defer CloseAllServers(servers)

			if err := testUDPConn(clientPort, 1024, time.Second*10)(); err != nil {
				t.Error(err)
			}
		})
	}
}
