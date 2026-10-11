package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/hysteria2"
	"github.com/xtls/xray-core/proxy/hysteria2/account"
	"google.golang.org/protobuf/proto"
)

type Hysteria2ClientConfig struct {
	Version int32    `json:"version"`
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

func (c *Hysteria2ClientConfig) Build() (proto.Message, error) {
	if c.Version != 2 {
		return nil, errors.New("version != 2")
	}

	config := &hysteria2.ClientConfig{}
	config.Server = &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
	}

	return config, nil
}

type Hysteria2UserConfig struct {
	Auth  string `json:"auth"`
	Level uint32 `json:"level"`
	Email string `json:"email"`
}

type Hysteria2ServerConfig struct {
	Version int32                  `json:"version"`
	Users   []*Hysteria2UserConfig `json:"users"`
	Clients []*Hysteria2UserConfig `json:"clients"`
}

func (c *Hysteria2ServerConfig) Build() (proto.Message, error) {
	if c.Version != 2 {
		return nil, errors.New("version != 2")
	}

	config := new(hysteria2.ServerConfig)

	if c.Clients != nil {
		c.Users = c.Clients
	}
	if len(c.Users) > 0 {
		config.Users = make([]*protocol.User, len(c.Users))
		processUser := func(idx int) error {
			user := c.Users[idx]
			acc := &account.Account{
				Auth: user.Auth,
			}
			config.Users[idx] = &protocol.User{
				Email:   user.Email,
				Level:   user.Level,
				Account: serial.ToTypedMessage(acc),
			}
			return nil
		}
		if err := task.ParallelForN(len(c.Users), processUser); err != nil {
			return nil, err
		}
	}

	return config, nil
}
