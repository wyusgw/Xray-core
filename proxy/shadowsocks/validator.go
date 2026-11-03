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

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
//
// 多用户 AEAD 协议里没有用户标识，验证时只能逐个用户试解。查找顺序：
// 1. 第一级：这个源 IP 之前成功过的用户（O(1)）
// 2. 第二级：最近成功过的用户，最近的在前（O(在线用户数)）
// 3. 全量扫描（O(总用户数)），按源 IP 限速，见 scanLimiter
type Validator struct {
	sync.RWMutex
	users      []*protocol.MemoryUser
	userPos    map[*protocol.MemoryUser]int    // 用户在 users 中的下标，删除时 O(1) 定位
	emailIndex map[string]*protocol.MemoryUser // Email -> User 的快速索引
	userCache  *UserCache                      // 基于源地址的用户缓存
	scanLimit  *scanLimiter                    // 全量扫描按源 IP 限速

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

// initializeIfNeeded 初始化索引和缓存（内部使用，调用者需持有锁）
func (v *Validator) initializeIfNeeded() {
	if v.emailIndex == nil {
		v.emailIndex = make(map[string]*protocol.MemoryUser)
	}
	if v.userPos == nil {
		v.userPos = make(map[*protocol.MemoryUser]int)
	}
	if v.userCache == nil {
		// 一级缓存（IP分片）2048 容量，LRU 淘汰；二级缓存（成功用户）按 TTL 淘汰
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

// removeAt 用末尾元素填补下标 idx 并缩短切片（调用者需持有写锁）
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

// UpdateUser 更新用户信息（如修改密码），会清除该用户的缓存
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

// GetWithCache 带两级缓存支持的用户验证
//
// cacheKey: 缓存键（客户端IP，不含端口：同一客户端每个连接的端口都不同），为空则跳过缓存和限速
func (v *Validator) GetWithCache(bs []byte, command protocol.RequestCommand, cacheKey string) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	t := &trialDecrypter{bs: bs, command: command}

	if cacheKey != "" && v.userCache != nil {
		ipUsers := v.userCache.GetMultiUser(cacheKey)

		// 第一级：这个IP之前成功过的用户；第二级：最近成功过的用户，
		// 最近的在前。都未命中才全量扫描。
		for _, user := range ipUsers {
			if t.try(user) && v.confirm(cacheKey, user) {
				return user, t.aead, t.ret, t.ivLen, nil
			}
		}
		for _, entry := range v.userCache.RecentUsers() {
			if slices.Contains(ipUsers, entry.user) {
				continue // 第一级已经试过
			}
			if t.try(entry.user) && v.confirm(cacheKey, entry.user) {
				return entry.user, t.aead, t.ret, t.ivLen, nil
			}
		}
	}

	v.RLock()
	totalUsers := len(v.users)
	limited := cacheKey != "" && v.scanLimit != nil && totalUsers >= scanLimitMinUsers
	if limited && !v.scanLimit.Allow(cacheKey) {
		// 这个IP最近的全量扫描都失败了（过期用户、扫描器），先不扫
		v.RUnlock()
		return nil, nil, nil, 0, ErrNotFound
	}

	// 随机起始位置，所有用户有平等的验证机会
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
		// 持有读锁更新缓存，不会与 Del 交错
		if cacheKey != "" && v.userCache != nil {
			v.userCache.PutWithSuccess(cacheKey, user)
		}
		v.RUnlock()
		if limited {
			v.scanLimit.Success(cacheKey)
		}
		return u, aead, ret, ivLen, nil
	}
	v.RUnlock()

	if limited {
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

// confirm 确认缓存命中的用户仍然有效，并在同一把读锁下更新缓存。Del 持有
// 写锁时从索引和缓存中移除用户：这里要么整个发生在 Del 之前（写入的缓存
// 条目随后被 Del 清除），要么在之后（用户已不在索引中而被拒绝），已删除
// 的用户不会因为并发的握手重新进入缓存。
func (v *Validator) confirm(cacheKey string, u *protocol.MemoryUser) bool {
	v.RLock()
	defer v.RUnlock()
	if u.Email != "" && v.emailIndex[strings.ToLower(u.Email)] != u {
		return false
	}
	v.userCache.PutWithSuccess(cacheKey, u)
	return true
}

// zeroNonce 是每个流的第一个块（TCP）或每个 UDP 包使用的全零 nonce，
// 足够任何支持的 AEAD 使用
var zeroNonce [24]byte

// trialDecrypter 用一个包的头部逐个尝试候选用户：多用户 AEAD 协议里没有
// 用户标识，只能逐个派生子密钥试解。它按盐长度复用子密钥派生的状态和
// 输出缓冲区，每个候选用户只分配 AEAD 本身。
type trialDecrypter struct {
	bs      []byte
	command protocol.RequestCommand
	kdfs    []saltKDF
	subkey  [32]byte
	out     []byte

	// 最近一次 try 成功时的结果
	aead  cipher.AEAD
	ret   []byte
	ivLen int32
}

type saltKDF struct {
	ivLen int32
	kdf   *subkeyKDF
}

// try 报告 user 的密钥能否解开这个包的头部，成功时结果存放在 t.aead、
// t.ret（解出的数据，UDP 为整个包的明文）和 t.ivLen 中。
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
		ciphertext = t.bs[ivLen : ivLen+18] // 2字节长度 + 16字节标签
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
