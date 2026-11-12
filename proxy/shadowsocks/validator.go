package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Lookup order: users matched from the source IP, removed users from it (rejected),
// recent users, then all users limited per IP and process, then removed users.
type Validator struct {
	sync.RWMutex
	users      []*protocol.MemoryUser
	userPos    map[*protocol.MemoryUser]int
	emailIndex map[string]*protocol.MemoryUser // lowercased email -> user
	userCache  *UserCache
	scanLimit  *scanLimiter
	retired    retiredUsers
	keyUsers   map[string]int

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

// initializeIfNeeded must be called with the write lock held.
func (v *Validator) initializeIfNeeded() {
	if v.emailIndex == nil {
		v.emailIndex = make(map[string]*protocol.MemoryUser)
	}
	if v.userPos == nil {
		v.userPos = make(map[*protocol.MemoryUser]int)
	}
	if v.keyUsers == nil {
		v.keyUsers = make(map[string]int)
	}
	if v.userCache == nil {
		v.userCache = NewUserCache(2048)
	}
	if v.scanLimit == nil {
		v.scanLimit = newScanLimiter()
	}
}

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}

	v.initializeIfNeeded()

	v.userPos[u] = len(v.users)
	v.users = append(v.users, u)
	v.useKey(u, 1)
	v.retired.remove(u)

	if u.Email != "" {
		v.emailIndex[strings.ToLower(u.Email)] = u
	}

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

// removeAt must be called with the write lock held.
func (v *Validator) removeAt(idx int) {
	last := len(v.users) - 1
	removed := v.users[idx]
	if idx != last {
		moved := v.users[last]
		v.users[idx] = moved
		v.userPos[moved] = idx
	}
	v.users[last] = nil
	v.users = v.users[:last]
	delete(v.userPos, removed)
}

// useKey must be called with the write lock held.
func (v *Validator) useKey(u *protocol.MemoryUser, delta int) {
	key, ok := retiredKey(u)
	if !ok {
		return
	}
	if n := v.keyUsers[key] + delta; n > 0 {
		v.keyUsers[key] = n
	} else {
		delete(v.keyUsers, key)
	}
}

// retire must be called with the write lock held.
func (v *Validator) retire(u *protocol.MemoryUser, now time.Time) {
	if key, ok := retiredKey(u); ok && v.keyUsers[key] == 0 {
		v.retired.add(u, now)
	}
}

func (v *Validator) Retire(users []*protocol.MemoryUser) {
	v.Lock()
	defer v.Unlock()
	v.initializeIfNeeded()
	now := time.Now()
	for _, u := range users {
		if u.Email != "" && v.emailIndex[strings.ToLower(u.Email)] != nil {
			continue
		}
		v.retire(u, now)
	}
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)

	user, exists := v.emailIndex[email]
	if !exists {
		return errors.New("User ", email, " not found.")
	}

	if idx, ok := v.userPos[user]; ok {
		v.removeAt(idx)
	}
	delete(v.emailIndex, email)
	v.useKey(user, -1)
	v.retire(user, time.Now())

	if v.userCache != nil {
		// Cached users are keyed by their own email, which may not be lowercase.
		v.userCache.Remove(user.Email)
	}

	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.RLock()
	defer v.RUnlock()

	if v.emailIndex == nil {
		return nil
	}
	return v.emailIndex[strings.ToLower(email)]
}

func (v *Validator) Has(u *protocol.MemoryUser) bool {
	v.RLock()
	defer v.RUnlock()
	_, ok := v.userPos[u]
	return ok
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.RLock()
	defer v.RUnlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.RLock()
	defer v.RUnlock()
	return int64(len(v.users))
}

func (v *Validator) UpdateUser(email string, newUser *protocol.MemoryUser) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)

	oldUser, exists := v.emailIndex[email]
	if !exists {
		return errors.New("User ", email, " not found.")
	}

	if idx, ok := v.userPos[oldUser]; ok {
		v.users[idx] = newUser
		delete(v.userPos, oldUser)
		v.userPos[newUser] = idx
	}
	v.useKey(oldUser, -1)
	v.useKey(newUser, 1)
	v.retire(oldUser, time.Now())
	v.retired.remove(newUser)

	delete(v.emailIndex, email)
	if newUser.Email != "" {
		v.emailIndex[strings.ToLower(newUser.Email)] = newUser
	}

	if v.userCache != nil {
		v.userCache.Remove(oldUser.Email)
	}

	return nil
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	return v.GetWithCache(bs, command, "")
}

func (v *Validator) GetWithCache(bs []byte, command protocol.RequestCommand, cacheKey string) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	t := &trialDecrypter{bs: bs, command: command}

	if cacheKey != "" && v.userCache != nil {
		ipUsers := v.userCache.GetMultiUser(cacheKey)
		for _, user := range ipUsers {
			if t.try(user) && v.confirm(cacheKey, user) {
				return user, t.aead, t.ret, t.ivLen, nil
			}
		}
		if v.scanLimit != nil {
			for _, user := range v.scanLimit.Retired(cacheKey) {
				if !t.try(user) {
					continue
				}
				if v.isRetired(user) {
					return nil, nil, nil, 0, ErrNotFound
				}
				v.scanLimit.DropRetired(cacheKey, user)
			}
		}
		recent := v.userCache.RecentUsers()
		if len(recent) > scanLimitedRecentUsers && v.scanThrottled(cacheKey) {
			recent = recent[:scanLimitedRecentUsers]
		}
		for _, entry := range recent {
			if slices.Contains(ipUsers, entry.user) {
				continue
			}
			if t.try(entry.user) && v.confirm(cacheKey, entry.user) {
				return entry.user, t.aead, t.ret, t.ivLen, nil
			}
		}
	}

	gated := v.scanKeys() >= scanLimitMinUsers
	limited := gated && cacheKey != "" && v.scanLimit != nil
	if limited && !v.scanLimit.Allow(cacheKey) {
		return nil, nil, nil, 0, ErrNotFound
	}
	if gated {
		// Wait without the lock so Add and Del are not blocked.
		if !acquireFullScan() {
			return nil, nil, nil, 0, ErrNotFound
		}
		defer releaseFullScan()
	}

	v.RLock()
	totalUsers := len(v.users)
	startIdx := 0
	if totalUsers > 1 {
		startIdx = rand.IntN(totalUsers)
	}
	for i := 0; i < totalUsers; i++ {
		user := v.users[(startIdx+i)%totalUsers]
		account := user.Account.(*MemoryAccount)
		if account.Cipher.IsAEAD() {
			if !t.try(user) {
				continue
			}
			u, aead, ret, ivLen = user, t.aead, t.ret, t.ivLen
		} else {
			u, ivLen = user, account.Cipher.IVSize()
		}
		// The read lock keeps this from racing with Del.
		if cacheKey != "" && v.userCache != nil {
			v.userCache.PutWithSuccess(cacheKey, user)
		}
		v.RUnlock()
		if limited {
			v.scanLimit.Success(cacheKey)
		}
		return u, aead, ret, ivLen, nil
	}
	var retired *protocol.MemoryUser
	if cacheKey != "" {
		retired = v.retired.match(t, time.Now())
	}
	v.RUnlock()

	switch {
	case retired != nil && v.scanLimit != nil:
		v.scanLimit.AddRetired(cacheKey, retired)
	case limited:
		v.scanLimit.Fail(cacheKey)
	}
	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = rand.Uint64()
	}
	return v.behaviorSeed
}

func (v *Validator) isRetired(u *protocol.MemoryUser) bool {
	v.RLock()
	defer v.RUnlock()
	return v.retired.contains(u)
}

func (v *Validator) scanKeys() int {
	v.RLock()
	defer v.RUnlock()
	return len(v.users) + len(v.retired.byKey)
}

func (v *Validator) scanThrottled(cacheKey string) bool {
	return v.scanLimit != nil && v.scanKeys() >= scanLimitMinUsers && !v.scanLimit.Allow(cacheKey)
}

// Under the read lock, so a concurrent Del cannot put a removed user back into the cache.
func (v *Validator) confirm(cacheKey string, u *protocol.MemoryUser) bool {
	v.RLock()
	defer v.RUnlock()
	if u.Email != "" && v.emailIndex[strings.ToLower(u.Email)] != u {
		return false
	}
	v.userCache.PutWithSuccess(cacheKey, u)
	return true
}

var zeroNonce [24]byte

type trialDecrypter struct {
	bs      []byte
	command protocol.RequestCommand
	kdfs    []saltKDF
	subkey  [32]byte
	out     []byte

	aead  cipher.AEAD
	ret   []byte
	ivLen int32
}

type saltKDF struct {
	ivLen int32
	kdf   *subkeyKDF
}

func (t *trialDecrypter) try(user *protocol.MemoryUser) bool {
	account, ok := user.Account.(*MemoryAccount)
	// AEAD payload decoding requires the payload to be over 32 bytes
	if !ok || !account.Cipher.IsAEAD() || len(t.bs) < 32 {
		return false
	}
	aeadCipher := account.Cipher.(*AEADCipher)
	ivLen := aeadCipher.IVSize()
	subkey := t.subkey[:aeadCipher.KeyBytes]
	t.saltKDF(ivLen).derive(account.Key, subkey)
	aead := aeadCipher.AEADAuthCreator(subkey)

	var ciphertext []byte
	switch t.command {
	case protocol.RequestCommandTCP:
		ciphertext = t.bs[ivLen : ivLen+18] // 2-byte length + 16-byte tag
	case protocol.RequestCommandUDP:
		ciphertext = t.bs[ivLen:]
	default:
		return false
	}
	if t.out == nil {
		t.out = make([]byte, 0, len(ciphertext))
	}
	ret, err := aead.Open(t.out[:0], zeroNonce[:aead.NonceSize()], ciphertext, nil)
	if err != nil {
		return false
	}
	t.aead, t.ret, t.ivLen = aead, ret, ivLen
	return true
}

func (t *trialDecrypter) saltKDF(ivLen int32) *subkeyKDF {
	for _, k := range t.kdfs {
		if k.ivLen == ivLen {
			return k.kdf
		}
	}
	k := newSubkeyKDF(t.bs[:ivLen])
	t.kdfs = append(t.kdfs, saltKDF{ivLen, k})
	return k
}
