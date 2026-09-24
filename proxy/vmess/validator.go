package vmess

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

// TimedUserValidator is a user Validator based on time.
type TimedUserValidator struct {
	sync.RWMutex
	users   []*protocol.MemoryUser
	byEmail map[string]int // lower-cased email -> position in users

	behaviorSeed  uint64
	behaviorFused bool

	aeadDecoderHolder *aead.AuthIDDecoderHolder
}

// NewTimedUserValidator creates a new TimedUserValidator.
func NewTimedUserValidator() *TimedUserValidator {
	tuv := &TimedUserValidator{
		users:             make([]*protocol.MemoryUser, 0, 16),
		byEmail:           make(map[string]int),
		aeadDecoderHolder: aead.NewAuthIDDecoderHolder(),
	}
	return tuv
}

func (v *TimedUserValidator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("account type is incorrect")
	}

	v.users = append(v.users, u)
	if u.Email != "" {
		v.byEmail[strings.ToLower(u.Email)] = len(v.users) - 1
	}
	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("VMESSBSKDF"))
		hashkdf.Write(account.ID.Bytes())
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	var cmdkeyfl [16]byte
	copy(cmdkeyfl[:], account.ID.CmdKey())
	v.aeadDecoderHolder.AddUser(cmdkeyfl, u)

	return nil
}

func (v *TimedUserValidator) GetUsers() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

func (v *TimedUserValidator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

func (v *TimedUserValidator) GetAEAD(userHash []byte) (*protocol.MemoryUser, bool, error) {
	return v.GetAEADFrom(userHash, "")
}

// GetAEADFrom is GetAEAD for a connection from source, the client's IP or
// "" if unknown.
func (v *TimedUserValidator) GetAEADFrom(userHash []byte, source string) (*protocol.MemoryUser, bool, error) {
	v.RLock()
	defer v.RUnlock()

	var userHashFL [16]byte
	copy(userHashFL[:], userHash)

	userd, err := v.aeadDecoderHolder.MatchFrom(userHashFL, source)
	if err != nil {
		return nil, false, err
	}
	return userd.(*protocol.MemoryUser), true, nil
}

func (v *TimedUserValidator) Remove(email string) bool {
	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx, ok := v.byEmail[email]
	if !ok {
		return false
	}
	var cmdkeyfl [16]byte
	copy(cmdkeyfl[:], v.users[idx].Account.(*MemoryAccount).ID.CmdKey())
	v.aeadDecoderHolder.RemoveUser(cmdkeyfl)
	delete(v.byEmail, email)

	last := len(v.users) - 1
	if idx != last {
		v.users[idx] = v.users[last]
		if moved := v.users[idx].Email; moved != "" {
			v.byEmail[strings.ToLower(moved)] = idx
		}
	}
	v.users[last] = nil
	v.users = v.users[:last]

	return true
}

func (v *TimedUserValidator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

var ErrNotFound = errors.New("Not Found")

var ErrTainted = errors.New("ErrTainted")
