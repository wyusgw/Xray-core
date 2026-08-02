package mieru

import (
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount is the in-memory form of Account. mieru derives its session
// keys from the user name as well as the password, so both are carried through.
type MemoryAccount struct {
	Username string
	Password string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		Username: a.Username,
		Password: a.Password,
	}, nil
}

func (m *MemoryAccount) Equals(another protocol.Account) bool {
	if o, ok := another.(*MemoryAccount); ok {
		return m.Username == o.Username && m.Password == o.Password
	}
	return false
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Username: m.Username,
		Password: m.Password,
	}
}
