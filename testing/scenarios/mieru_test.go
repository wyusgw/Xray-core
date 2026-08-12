package scenarios

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/stats"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/mieru"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func newMieruUsername() string {
	id := uuid.New()
	return id.String()
}

func mieruLogConfig() []*serial.TypedMessage {
	return []*serial.TypedMessage{
		serial.ToTypedMessage(&log.Config{
			ErrorLogLevel: clog.Severity_Warning,
			ErrorLogType:  log.LogType_Console,
		}),
	}
}

// mieruStreamConfig is the "network": "mieru" transport the inbound listens on.
// Only the server side has one: the outbound dials mieru itself, so it rides on
// no Xray transport at all.
func mieruStreamConfig() *internet.StreamConfig {
	return &internet.StreamConfig{ProtocolName: "mieru"}
}

// mieruConfigs builds a server and a client that talk to each other over mieru.
// transport selects mieru's underlay, "TCP" or "UDP", which is unrelated to the
// network of the traffic being proxied.
func mieruConfigs(serverPort net.Port, username, password, transport string) (*core.Config, *core.Config) {
	serverConfig := &core.Config{
		App: mieruLogConfig(),
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "mieru-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:         net.NewIPOrDomain(net.LocalHostIP),
					StreamSettings: mieruStreamConfig(),
				}),
				ProxySettings: serial.ToTypedMessage(&mieru.ServerConfig{
					Transport: transport,
					Users: []*protocol.User{
						{
							Email: "mieru-user@test",
							Account: serial.ToTypedMessage(&mieru.Account{
								Username: username,
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
		App: mieruLogConfig(),
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&mieru.ClientConfig{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&mieru.Account{
								Username: username,
								Password: password,
							}),
						},
					},
					Transport: transport,
				}),
			},
		},
	}

	return serverConfig, clientConfig
}

func TestMieruTCP(t *testing.T) {
	for _, transport := range []string{"TCP", "UDP"} {
		t.Run(transport, func(t *testing.T) {
			tcpServer := tcp.Server{MsgProcessor: xor}
			dest, err := tcpServer.Start()
			common.Must(err)
			defer tcpServer.Close()

			serverConfig, clientConfig := mieruConfigs(tcp.PickPort(), newMieruUsername(), "mieru-password", transport)

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

			if err := testTCPConn(clientPort, 10240, time.Second*20)(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestMieruUDP(t *testing.T) {
	udpServer := udp.Server{MsgProcessor: xor}
	udpDest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	serverConfig, clientConfig := mieruConfigs(tcp.PickPort(), newMieruUsername(), "mieru-password", "TCP")

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
}

// TestMieruAddUser checks that a user added after the server is already
// listening can connect without the inbound being restarted, which is what the
// panel relies on when it syncs its user list.
func TestMieruAddUser(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	// The server starts knowing only the first user.
	serverPort := tcp.PickPort()
	serverConfig, _ := mieruConfigs(serverPort, newMieruUsername(), "mieru-password", "TCP")

	lateUsername := newMieruUsername()
	_, clientConfig := mieruConfigs(serverPort, lateUsername, "late-password", "TCP")

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

	// The commander is how the panel drives user changes at runtime.
	cmdPort := tcp.PickPort()
	serverConfig.App = append(serverConfig.App, serial.ToTypedMessage(&commander.Config{
		Tag:    "api",
		Listen: fmt.Sprintf("127.0.0.1:%d", cmdPort),
		Service: []*serial.TypedMessage{
			serial.ToTypedMessage(&command.Config{}),
		},
	}))

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	// The late user is not known yet, so the handshake must not succeed.
	if err := testTCPConn(clientPort, 1024, time.Second*5)(); err == nil {
		t.Error("expected the connection to fail before the user was added")
	}

	cmdConn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", cmdPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	common.Must(err)
	defer cmdConn.Close()

	hsClient := command.NewHandlerServiceClient(cmdConn)
	_, err = hsClient.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: "mieru-in",
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email: "late@test",
				Account: serial.ToTypedMessage(&mieru.Account{
					Username: lateUsername,
					Password: "late-password",
				}),
			},
		}),
	})
	common.Must(err)

	// The listener was never restarted, so this only passes if the new user
	// reached mieru's Mux while it was running.
	if err := testTCPConn(clientPort, 10240, time.Second*20)(); err != nil {
		t.Error("expected the connection to succeed after the user was added: ", err)
	}

	_, err = hsClient.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag:       "mieru-in",
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "late@test"}),
	})
	common.Must(err)
}

// TestMieruUserStats checks that traffic is attributed to the mieru user that
// carried it, which is what a panel reports on.
func TestMieruUserStats(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverConfig, clientConfig := mieruConfigs(tcp.PickPort(), newMieruUsername(), "mieru-password", "TCP")

	// Per-user counters are only kept for levels whose policy asks for them, and
	// the users built above sit at the default level 0.
	cmdPort := tcp.PickPort()
	serverConfig.App = append(serverConfig.App,
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&policy.Config{
			Level: map[uint32]*policy.Policy{
				0: {
					Stats: &policy.Policy_Stats{
						UserUplink:   true,
						UserDownlink: true,
					},
				},
			},
		}),
		serial.ToTypedMessage(&commander.Config{
			Tag:    "api",
			Listen: fmt.Sprintf("127.0.0.1:%d", cmdPort),
			Service: []*serial.TypedMessage{
				serial.ToTypedMessage(&statscmd.Config{}),
			},
		}),
	)

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

	const payload = 10240
	if err := testTCPConn(clientPort, payload, time.Second*20)(); err != nil {
		t.Fatal(err)
	}

	cmdConn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", cmdPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	common.Must(err)
	defer cmdConn.Close()

	sClient := statscmd.NewStatsServiceClient(cmdConn)
	resp, err := sClient.GetStats(context.Background(), &statscmd.GetStatsRequest{
		Name: "user>>>mieru-user@test>>>traffic>>>uplink",
	})
	common.Must(err)
	if resp.Stat.Value < payload {
		t.Error("expected at least ", payload, " uplink bytes for the mieru user, got ", resp.Stat.Value)
	}
}
