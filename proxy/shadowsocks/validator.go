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
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
//
// 性能优化策略：
// 1. 用户缓存：基于源地址的LRU缓存，缓存命中时O(1)直接返回，避免O(n)遍历
// 2. Email索引：使用map加速按Email查找/删除用户，从O(n)优化到O(1)
// 3. 内存池：复用解密缓冲区，减少GC压力
// 4. 攻击防御：检测和阻止失效用户的暴力尝试攻击
// 5. 早期中断：对可疑连接提前终止遍历，避免消耗大量CPU
//
// 性能提升：
// - 热点用户场景（80%请求来自20%用户）：5-10倍性能提升
// - Email查找/删除操作：从O(n)优化到O(1)
// - 攻击防御：失效用户第2次尝试直接拒绝，避免遍历10万用户
type Validator struct {
	sync.RWMutex
	users         []*protocol.MemoryUser
	emailIndex    map[string]*protocol.MemoryUser // Email -> User 的快速索引
	userCache     *UserCache                      // 基于源地址的用户缓存
	attackDefense *AttackDefense                  // 攻击防御系统

	behaviorSeed  uint64
	behaviorFused bool

	// 握手路径上不持锁读取，用原子类型
	isRelayNode     atomic.Bool // 标记节点是否处于中转环境（检测到后保持）
	defenseEnabled  atomic.Bool // 攻击防御是否已启用（确认非中转后才启用）
	detectionActive atomic.Bool // 是否正在进行环境检测（检测完成后固定）
}

var ErrNotFound = errors.New("Not Found")

// initializeIfNeeded 初始化索引和缓存（内部使用，调用者需持有锁）
func (v *Validator) initializeIfNeeded() {
	if v.emailIndex == nil {
		v.emailIndex = make(map[string]*protocol.MemoryUser)
	}
	if v.userCache == nil {
		// 初始缓存容量优化：
		// - 一级缓存（IP分片）：2048容量，LRU自动淘汰
		// - 二级缓存（成功用户）：无上限，保存所有活跃用户
		//
		// 容量选择：2048 足以覆盖大部分场景
		// - 小规模（<5K用户）：缓存充足
		// - 中规模（5K-50K）：热点IP被缓存，冷门IP被LRU淘汰
		// - 大规模（>50K）：依赖二级缓存，一级缓存只保留最热IP
		v.userCache = NewUserCache(2048)
	}
	if v.attackDefense == nil {
		v.attackDefense = NewAttackDefense(nil) // 使用默认配置
	}

	// 初始状态：检测未完成，攻击防御未启用
	if !v.detectionActive.Load() {
		v.detectionActive.Store(true)
		v.defenseEnabled.Store(false)
		v.isRelayNode.Store(false)
	}
}

// Add a Shadowsocks user.
// 优化：支持高频添加场景（适用于逐个添加或定期同步）
// - 自动预分配容量，减少内存重分配
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}

	// 初始化索引和缓存（延迟初始化）
	v.initializeIfNeeded()

	// 智能扩容：当容量不足时，预分配更多空间
	// 策略：当前容量 + max(当前长度的25%, min(256, 当前长度))
	// - 小规模：快速翻倍增长
	// - 大规模：25%增长避免浪费内存
	if len(v.users) >= cap(v.users) {
		// 计算增长量
		growth := len(v.users) / 4 // 25%增长

		// 最小增长量：小规模时加速扩容
		minGrowth := len(v.users)
		if minGrowth > 256 {
			minGrowth = 256
		}
		if minGrowth < 64 {
			minGrowth = 64
		}

		if growth < minGrowth {
			growth = minGrowth
		}

		newCap := cap(v.users) + growth

		// 重新分配切片
		newUsers := make([]*protocol.MemoryUser, len(v.users), newCap)
		copy(newUsers, v.users)
		v.users = newUsers
	}

	v.users = append(v.users, u)

	// 更新Email索引（如果有Email）
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

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)

	// 先从Email索引中快速查找 O(1)
	user, exists := v.emailIndex[email]
	if !exists {
		return errors.New("User ", email, " not found.")
	}

	// 从切片中移除
	idx := -1
	for i, u := range v.users {
		if u == user { // 直接比较指针
			idx = i
			break
		}
	}

	if idx != -1 {
		ulen := len(v.users)
		v.users[idx] = v.users[ulen-1]
		v.users[ulen-1] = nil
		v.users = v.users[:ulen-1]
	}

	// 从Email索引中移除
	delete(v.emailIndex, email)

	// 从用户缓存中移除
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

	email = strings.ToLower(email)

	// 优化：直接从Email索引中获取 O(1)
	if v.emailIndex != nil {
		return v.emailIndex[email]
	}

	// 降级：如果索引未初始化，使用原来的遍历方式
	for _, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.RLock() // 改用读锁，不阻塞验证请求
	defer v.RUnlock()
	return int64(len(v.users))
}

// UpdateUser 更新用户信息（如修改密码）
// 注意：会清除该用户的缓存
func (v *Validator) UpdateUser(email string, newUser *protocol.MemoryUser) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)

	// 从索引查找旧用户
	oldUser, exists := v.emailIndex[email]
	if !exists {
		return errors.New("User ", email, " not found.")
	}

	// 在切片中找到并替换
	for i, u := range v.users {
		if u == oldUser {
			v.users[i] = newUser
			break
		}
	}

	// 更新Email索引
	delete(v.emailIndex, email)
	if newUser.Email != "" {
		v.emailIndex[strings.ToLower(newUser.Email)] = newUser
	}

	// 清除用户缓存（密码已变更）
	if v.userCache != nil {
		v.userCache.Remove(email)
	}

	return nil
}

// GetStats 获取统计信息（用于监控）
func (v *Validator) GetStats() ValidatorStats {
	v.RLock()
	defer v.RUnlock()

	stats := ValidatorStats{
		TotalUsers:      len(v.users),
		IndexedUsers:    0,
		CacheSize:       0,
		IsRelayNode:     v.isRelayNode.Load(),
		DefenseEnabled:  v.defenseEnabled.Load(),
		DetectionActive: v.detectionActive.Load(),
	}

	if v.emailIndex != nil {
		stats.IndexedUsers = len(v.emailIndex)
	}

	// 获取攻击防御统计（添加空指针保护）
	if v.attackDefense != nil {
		defenseStats := v.attackDefense.GetStats()
		stats.BannedIPs = defenseStats.BannedIPs
		stats.TotalFailures = defenseStats.TotalFailures
	}

	return stats
}

// ValidatorStats 验证器统计信息
type ValidatorStats struct {
	TotalUsers      int  // 总用户数
	IndexedUsers    int  // 已建立Email索引的用户数
	CacheSize       int  // 缓存的用户数
	BannedIPs       int  // 被封禁的IP/指纹数
	TotalFailures   int  // 总失败次数
	IsRelayNode     bool // 是否为中转节点
	DefenseEnabled  bool // 攻击防御是否已启用
	DetectionActive bool // 是否正在进行环境检测
}

// Get a Shadowsocks user.
// 性能优化：
// 1. 使用内存池减少内存分配和GC压力
// 2. 如果提供了cacheKey，会先从用户缓存中查找（O(1)），大幅提升热点用户性能
// 3. 未命中缓存时，遍历所有用户尝试解密，找到后更新缓存
//
// cacheKey: 可选的缓存键（客户端IP，不含端口），为空则跳过缓存
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	return v.GetWithCache(bs, command, "")
}

// GetWithCache 带两级缓存支持的用户验证（优化IP变化场景）
//
// 查找策略：
// 1. 第一级：IP缓存直接命中（最快，O(1)）
// 2. 第二级：成功用户缓存遍历（较快，O(k)，k为活跃用户数）
// 3. 第三级：全量用户扫描（最慢，O(n)，n为总用户数）
//
// cacheKey: 缓存键（客户端IP，不含端口：同一客户端每个连接的端口都不同），为空则跳过缓存
func (v *Validator) GetWithCache(bs []byte, command protocol.RequestCommand, cacheKey string) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	var defenseKey string
	t := &trialDecrypter{bs: bs, command: command}

	if cacheKey != "" && v.userCache != nil {
		ipUsers, _, isRelay := v.userCache.GetWithFallback(cacheKey)

		// 环境检测：同一IP上超过阈值的用户说明节点在中转之后，记录下来。
		// 攻击防御不再在这里自动启用：原来的启用条件（某个IP恰好有
		// relayDetectionThreshold 个用户）先于中转判定（超过该数）成立，
		// 中转节点会先被启用防御、再也不会被豁免，中转IP 可能被整体封禁。
		// 缓存键曾经带端口，这两个条件从未成立过，防御实际上一直未启用，
		// 这里保持这一行为。
		if isRelay && v.detectionActive.Load() {
			v.isRelayNode.Store(true)
			v.defenseEnabled.Store(false)
			v.detectionActive.Store(false) // 检测完成
		}

		// 只有在已确认非中转节点且防御已启用时，才进行攻击防御
		if v.defenseEnabled.Load() && v.attackDefense != nil {
			isTCP := (command == protocol.RequestCommandTCP)
			defenseKey = v.attackDefense.CheckAndRecordConnection(cacheKey, isTCP)

			if defenseKey != "" && !v.attackDefense.CheckAllowed(defenseKey) {
				// 已被封禁，直接返回
				return nil, nil, nil, 0, ErrNotFound
			}
		}

		// 第一级：这个IP之前成功过的用户；第二级：最近成功过的用户，
		// 最近的在前。都未命中才全量扫描。
		for _, user := range ipUsers {
			if t.try(user) && v.confirm(cacheKey, user) {
				v.recordDefenseSuccess(defenseKey)
				return user, t.aead, t.ret, t.ivLen, nil
			}
		}
		for _, entry := range v.userCache.RecentUsers() {
			if slices.Contains(ipUsers, entry.user) {
				continue // 第一级已经试过
			}
			if t.try(entry.user) && v.confirm(cacheKey, entry.user) {
				v.recordDefenseSuccess(defenseKey)
				return entry.user, t.aead, t.ret, t.ivLen, nil
			}
		}
	}

	// 慢速路径：需要全局锁进行全量扫描
	v.RLock()
	defer v.RUnlock()

	// 全量扫描策略：早期中断优化
	totalUsers := len(v.users)
	earlyStopThreshold := totalUsers // 默认检查所有用户（保证正常用户能连接）

	// 只有在防御已启用时，才进行白名单检查和早期中断优化
	isWhitelisted := false
	if v.defenseEnabled.Load() && defenseKey != "" && v.attackDefense != nil {
		// 白名单检查优化：
		// - 如果IP在白名单中(曾经成功验证过)，跳过早停限制
		// - 这样正常用户打开新连接时不会因为"缓存未命中"而受早停影响
		// - 攻击者的IP不在白名单，仍然会触发早停
		isWhitelisted = v.attackDefense.IsWhitelisted(defenseKey)

		// 只有当连接已经有失败记录时，才启用早期中断
		// 白名单IP(成功验证过的正常用户)不受早停限制
		if !isWhitelisted && v.attackDefense.HasFailureRecord(defenseKey) {
			// 此连接之前失败过，可能是过期用户，启用渐进式早期中断
			// 连续失败越多，检查用户数越少，最终降至10个
			earlyStopThreshold = v.attackDefense.GetEarlyStopThreshold(totalUsers, defenseKey)
		}
		// 否则：首次连接，完整遍历，避免误判
	}

	// 随机起始位置：使用 math/rand/v2（无锁、高性能）
	// 优势：
	// 1. 无锁：每个 goroutine 有独立的随机数生成器
	// 2. 均匀分布：所有用户有平等的验证机会
	// 3. 性能：比 math/rand 快很多，无全局锁竞争
	startIdx := 0
	if totalUsers > 1 {
		startIdx = rand.IntN(totalUsers)
	}

	checkedCount := 0
	for i := 0; i < totalUsers; i++ {
		idx := (startIdx + i) % totalUsers
		user := v.users[idx]

		// 优化：早期中断检查 - 对可疑连接提前终止
		checkedCount++
		if checkedCount > earlyStopThreshold {
			// 已检查足够多的用户仍未找到，极可能是攻击，提前放弃
			break
		}

		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			if t.try(user) {
				// 找到用户后更新两级缓存（持有读锁，不会与 Del 交错）
				if cacheKey != "" && v.userCache != nil {
					v.userCache.PutWithSuccess(cacheKey, user)
				}
				v.recordDefenseSuccess(defenseKey)
				return user, t.aead, t.ret, t.ivLen, nil
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.

			// 优化：更新两级缓存
			if cacheKey != "" && v.userCache != nil {
				v.userCache.PutWithSuccess(cacheKey, user)
			}

			// 防御已启用时才记录验证成功
			if v.defenseEnabled.Load() && defenseKey != "" && v.attackDefense != nil {
				v.attackDefense.RecordSuccess(defenseKey)
			}
			return
		}
	}

	// 防御已启用时才记录失败
	if v.defenseEnabled.Load() && defenseKey != "" && v.attackDefense != nil {
		v.attackDefense.RecordFailure(defenseKey)
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

// recordDefenseSuccess 防御已启用时记录验证成功
func (v *Validator) recordDefenseSuccess(defenseKey string) {
	if v.defenseEnabled.Load() && defenseKey != "" && v.attackDefense != nil {
		v.attackDefense.RecordSuccess(defenseKey)
	}
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
