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

// Validator stores valid Shadowsocks users.
//
// Multi-user AEAD carries no user ID, so a request is matched by trying each
// user's key. Lookup order:
//  1. users that succeeded from the same source IP before
//  2. removed users whose clients connect from the source IP: rejected
//  3. users that succeeded recently, most recent first
//  4. all users, limited per source IP (see scanLimiter) and in the process
//     (see acquireFullScan); then removed users, to recognize expired clients
type Validator struct {
	sync.RWMutex
	users      []*protocol.MemoryUser
	userPos    map[*protocol.MemoryUser]int    // index of each user in users
	emailIndex map[string]*protocol.MemoryUser // lowercased email -> user
	userCache  *UserCache                      // users keyed by source IP
	scanLimit  *scanLimiter                    // limits failed full scans per source IP
	retired    retiredUsers                    // keys of removed users
	keyUsers   map[string]int                  // users per AEAD key

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

// removeAt removes users[idx] by moving the last user into its place.
// It must be called with the write lock held.
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

// useKey counts users of the key of u. It must be called with the write lock
// held.
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

// retire records u as removed unless another user has the same key. It must
// be called with the write lock held.
func (v *Validator) retire(u *protocol.MemoryUser, now time.Time) {
	if key, ok := retiredKey(u); ok && v.keyUsers[key] == 0 {
		v.retired.add(u, now)
	}
}

// Retire records users that were removed while they were not in v, such as
// before the process started, so that their clients are recognized. Users
// that are in v, or share a key with one, are skipped.
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
		v.userCache.Remove(email)
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

// UpdateUser replaces the user with the given email and drops it from the cache.
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
	// Clients still using the old key are like clients of a removed user.
	v.retire(oldUser, time.Now())
	v.retired.remove(newUser)

	delete(v.emailIndex, email)
	if newUser.Email != "" {
		v.emailIndex[strings.ToLower(newUser.Email)] = newUser
	}

	if v.userCache != nil {
		v.userCache.Remove(email)
	}

	return nil
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	return v.GetWithCache(bs, command, "")
}

// GetWithCache is like Get, but uses cacheKey (the client IP without port)
// to look up cached users and to rate-limit full scans. An empty cacheKey
// disables both.
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
		// There can be as many recent users as users, so a throttled IP
		// only tries the most recent ones.
		recent := v.userCache.RecentUsers()
		if len(recent) > scanLimitedRecentUsers && v.scanThrottled(cacheKey) {
			recent = recent[:scanLimitedRecentUsers]
		}
		for _, entry := range recent {
			if slices.Contains(ipUsers, entry.user) {
				continue // already tried
			}
			if t.try(entry.user) && v.confirm(cacheKey, entry.user) {
				return entry.user, t.aead, t.ret, t.ivLen, nil
			}
		}
	}

	// Full scans are cheap with few keys to try: do not limit them.
	gated := v.scanKeys() >= scanLimitMinUsers
	limited := gated && cacheKey != "" && v.scanLimit != nil
	if limited && !v.scanLimit.Allow(cacheKey) {
		// Recent full scans from this IP matched nobody: probes or junk.
		return nil, nil, nil, 0, ErrNotFound
	}
	if gated {
		// Wait for a slot without holding the lock, so that Add and Del
		// are not blocked meanwhile.
		if !acquireFullScan() {
			return nil, nil, nil, 0, ErrNotFound
		}
		defer releaseFullScan()
	}

	v.RLock()
	totalUsers := len(v.users)
	// Start at a random user so that every user is equally fast to match.
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
		// Holding the read lock keeps this from racing with Del.
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
		// A client of a removed user: reject it cheaply from now on,
		// without limiting other clients behind the same IP.
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

// isRetired reports whether u is a removed user that is not in use again.
func (v *Validator) isRetired(u *protocol.MemoryUser) bool {
	v.RLock()
	defer v.RUnlock()
	return v.retired.contains(u)
}

// scanKeys returns how many keys a failed full scan tries: every user, then
// every removed user.
func (v *Validator) scanKeys() int {
	v.RLock()
	defer v.RUnlock()
	return len(v.users) + len(v.retired.byKey)
}

// scanThrottled reports whether full scans from cacheKey are being limited.
func (v *Validator) scanThrottled(cacheKey string) bool {
	return v.scanLimit != nil && v.scanKeys() >= scanLimitMinUsers && !v.scanLimit.Allow(cacheKey)
}

// confirm checks that a cached user has not been removed and caches it for
// cacheKey under the same read lock. Del removes users under the write lock,
// so a concurrent handshake cannot put a removed user back into the cache.
func (v *Validator) confirm(cacheKey string, u *protocol.MemoryUser) bool {
	v.RLock()
	defer v.RUnlock()
	if u.Email != "" && v.emailIndex[strings.ToLower(u.Email)] != u {
		return false
	}
	v.userCache.PutWithSuccess(cacheKey, u)
	return true
}

// zeroNonce is the nonce of the first TCP chunk and of every UDP packet.
var zeroNonce [24]byte

// trialDecrypter tries candidate users' keys against one request header.
// It reuses the subkey derivation state for each salt length and the output
// buffer, so each candidate only allocates its AEAD.
type trialDecrypter struct {
	bs      []byte
	command protocol.RequestCommand
	kdfs    []saltKDF
	subkey  [32]byte
	out     []byte

	// results of the last successful try
	aead  cipher.AEAD
	ret   []byte
	ivLen int32
}

type saltKDF struct {
	ivLen int32
	kdf   *subkeyKDF
}

// try reports whether user's key opens the request header. On success the
// results are in t.aead, t.ret (for UDP, the whole plaintext) and t.ivLen.
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
