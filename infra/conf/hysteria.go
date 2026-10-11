package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/hysteria2/account"
	"google.golang.org/protobuf/proto"
)

// HysteriaClientConfig is the first Hysteria generation, the `hysteria`
// outbound; the second generation is `hysteria2`.
type HysteriaClientConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	Auth    string   `json:"auth"`
	// Rates the client can send and receive, e.g. "20 mbps". Both are required.
	Up   Bandwidth `json:"up"`
	Down Bandwidth `json:"down"`
	// "xplus" is the only obfuscation of this generation.
	Obfs          string   `json:"obfs"`
	ObfsPassword  string   `json:"obfsPassword"`
	ServerName    string   `json:"serverName"`
	AllowInsecure bool     `json:"allowInsecure"`
	Alpn          []string `json:"alpn"`
}

func (c *HysteriaClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("hysteria: server address is required")
	}
	if c.Port == 0 {
		return nil, errors.New("hysteria: server port is required")
	}
	up, err := c.Up.Bps()
	if err != nil {
		return nil, errors.New("hysteria: bad up speed").Base(err)
	}
	down, err := c.Down.Bps()
	if err != nil {
		return nil, errors.New("hysteria: bad down speed").Base(err)
	}
	if up == 0 || down == 0 {
		return nil, errors.New("hysteria: up and down speed are required")
	}
	if c.Obfs != "" && c.Obfs != "xplus" {
		return nil, errors.New("hysteria: unsupported obfs ", c.Obfs)
	}
	if c.Obfs == "xplus" && c.ObfsPassword == "" {
		return nil, errors.New("hysteria: obfsPassword is required with xplus")
	}

	config := &hysteria.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
		},
		Auth:          c.Auth,
		UpBps:         up,
		DownBps:       down,
		ServerName:    c.ServerName,
		AllowInsecure: c.AllowInsecure,
		Alpn:          c.Alpn,
	}
	if c.Obfs == "xplus" {
		config.ObfsPassword = c.ObfsPassword
	}
	return config, nil
}

// HysteriaUserConfig is a user of the first Hysteria generation; Auth is the
// secret its client sends.
type HysteriaUserConfig struct {
	Auth  string `json:"auth"`
	Level uint32 `json:"level"`
	Email string `json:"email"`
}

// HysteriaServerConfig is the first Hysteria generation, the `hysteria`
// inbound; it needs the `hysteria` transport underneath.
type HysteriaServerConfig struct {
	Users   []*HysteriaUserConfig `json:"users"`
	Clients []*HysteriaUserConfig `json:"clients"`
}

func (c *HysteriaServerConfig) Build() (proto.Message, error) {
	config := new(hysteria.ServerConfig)

	users := c.Users
	if c.Clients != nil {
		users = c.Clients
	}
	for _, user := range users {
		config.Users = append(config.Users, &protocol.User{
			Email:   user.Email,
			Level:   user.Level,
			Account: serial.ToTypedMessage(&account.Account{Auth: user.Auth}),
		})
	}
	return config, nil
}
