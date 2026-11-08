package account

import (
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	var VR net.Port
	if id, err := uuid.Parse(a.Auth); err == nil {
		VR = net.PortFromBytes(id[6:8])
	}
	return &MemoryAccount{
		Auth: a.Auth,
		VR:   VR,
	}, nil
}

type MemoryAccount struct {
	Auth string
	VR   net.Port
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Auth == b.Auth
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Auth: a.Auth,
	}
}

type Validator struct {
	users  sync.Map // auth -> *protocol.MemoryUser
	ids    sync.Map
	emails sync.Map // email -> auth, so removing a user does not scan all users
	mu     sync.Mutex
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Add(user *protocol.MemoryUser) (err error) {
	v.mu.Lock()
	auth := user.Account.(*MemoryAccount).Auth
	if user.Email != "" {
		// Re-adding an email with a new auth replaces its old auth.
		if old, ok := v.emails.Load(user.Email); ok && old.(string) != auth {
			v.delAuth(old.(string), user.Email)
		}
		v.emails.Store(user.Email, auth)
	}
	v.users.Store(auth, user)
	if id, err := uuid.Parse(auth); err == nil {
		id[6] = 0
		id[7] = 0
		v.ids.Store(id, user)
	}
	v.mu.Unlock()
	return
}

func (v *Validator) DelByEmail(email string) (err error) {
	v.mu.Lock()
	if email == "" {
		if user := v.GetByEmail(email); user != nil {
			v.delAuth(user.Account.(*MemoryAccount).Auth, email)
		}
	} else if auth, ok := v.emails.LoadAndDelete(email); ok {
		v.delAuth(auth.(string), email)
	}
	v.mu.Unlock()
	return
}

// delAuth removes auth if it still belongs to email: a later Add may have
// given the same auth to another user. The caller holds v.mu.
func (v *Validator) delAuth(auth string, email string) {
	value, ok := v.users.Load(auth)
	if !ok || value.(*protocol.MemoryUser).Email != email {
		return
	}
	v.users.Delete(auth)
	if id, err := uuid.Parse(auth); err == nil {
		id[6] = 0
		id[7] = 0
		if value, ok := v.ids.Load(id); ok && value.(*protocol.MemoryUser).Email == email {
			v.ids.Delete(id)
		}
	}
}

func (v *Validator) Get(auth string) (user *protocol.MemoryUser) {
	if id, err := uuid.Parse(auth); err == nil {
		if user = v.GetByID(id); user != nil {
			VR := net.PortFromBytes(id[6:8])
			if user.Account.(*MemoryAccount).VR != VR {
				user = &protocol.MemoryUser{
					Email: user.Email,
					Level: user.Level,
					Account: &MemoryAccount{
						Auth: auth,
						VR:   VR,
					},
				}
			}
		}
		return
	}
	if value, ok := v.users.Load(auth); ok {
		user = value.(*protocol.MemoryUser)
	}
	return
}

func (v *Validator) GetByID(id uuid.UUID) (user *protocol.MemoryUser) {
	id[6] = 0
	id[7] = 0
	if value, ok := v.ids.Load(id); ok {
		user = value.(*protocol.MemoryUser)
	}
	return
}

func (v *Validator) GetByEmail(email string) (user *protocol.MemoryUser) {
	if email != "" {
		if auth, ok := v.emails.Load(email); ok {
			if value, ok := v.users.Load(auth); ok && value.(*protocol.MemoryUser).Email == email {
				user = value.(*protocol.MemoryUser)
			}
		}
		return
	}
	v.users.Range(func(key, value any) bool {
		if value.(*protocol.MemoryUser).Email == email {
			user = value.(*protocol.MemoryUser)
			return false
		}
		return true
	})
	return
}

func (v *Validator) GetAll() (users []*protocol.MemoryUser) {
	v.users.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return
}

func (v *Validator) GetCount() (count int64) {
	v.users.Range(func(key, value any) bool {
		count++
		return true
	})
	return
}

func (v *Validator) NotEmpty() (not_empty bool) {
	v.users.Range(func(key, value any) bool {
		not_empty = true
		return false
	})
	return
}
