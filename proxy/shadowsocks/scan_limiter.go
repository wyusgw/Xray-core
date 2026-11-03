package shadowsocks

import (
	"sync"
	"time"
)

// 多用户 AEAD 握手在缓存未命中时只能逐个用户试解，成本与用户总数成正比。
// 过期用户的客户端、扫描器每次连接都会触发一次全量扫描，用户多时会吃满
// CPU。scanLimiter 给每个源 IP 一个令牌桶：只有失败的全量扫描消耗令牌，
// 成功的不消耗，所以正常用户不受影响；令牌耗尽的 IP 在恢复前跳过全量扫描，
// 只尝试 IP 缓存和最近成功的前 scanLimitedRecentUsers 个用户。
const (
	// scanLimitMinUsers 用户数低于这个值时全量扫描很便宜，不做限制
	scanLimitMinUsers = 256

	// scanBurst 每个 IP 连续失败的全量扫描次数上限
	scanBurst = 8
	// scanRefill 每隔多久恢复一个令牌
	scanRefill = 2 * time.Second

	// scanLimitedRecentUsers 被限速的IP最多试多少个最近成功用户
	scanLimitedRecentUsers = 64

	scanShards = 32
	// scanShardCap 每个分片最多跟踪的 IP 数，32 个分片共约 13 万个，
	// 每条约 100 字节，上限十几 MB
	scanShardCap = 4096
)

type scanBucket struct {
	tokens float64
	last   int64 // UnixNano，tokens 对应的时间
}

type scanShard struct {
	mu      sync.Mutex
	buckets map[string]*scanBucket
}

type scanLimiter struct {
	shards [scanShards]scanShard
}

func newScanLimiter() *scanLimiter {
	l := &scanLimiter{}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*scanBucket)
	}
	return l
}

func (l *scanLimiter) shard(key string) *scanShard {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &l.shards[h%scanShards]
}

// refilled 返回 b 在 now 时刻的令牌数
func (b *scanBucket) refilled(now int64) float64 {
	t := b.tokens + float64(now-b.last)/float64(scanRefill)
	if t > scanBurst {
		t = scanBurst
	}
	return t
}

// Allow 报告 key 现在是否还能做一次全量扫描
func (l *scanLimiter) Allow(key string) bool {
	if key == "" {
		return true
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		return true
	}
	return b.refilled(time.Now().UnixNano()) >= 1
}

// Fail 记录 key 的一次失败全量扫描
func (l *scanLimiter) Fail(key string) {
	if key == "" {
		return
	}
	now := time.Now().UnixNano()
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) >= scanShardCap {
			s.evict(now)
		}
		b = &scanBucket{tokens: scanBurst, last: now}
		s.buckets[key] = b
	}
	b.tokens = b.refilled(now) - 1
	if b.tokens < 0 {
		b.tokens = 0
	}
	b.last = now
}

// Success 清除 key 的失败记录
func (l *scanLimiter) Success(key string) {
	if key == "" {
		return
	}
	s := l.shard(key)
	s.mu.Lock()
	delete(s.buckets, key)
	s.mu.Unlock()
}

// evict 在分片满时腾出空间：先删已经恢复满的桶（等同于没有记录），
// 都没恢复满就随机删一部分，保证内存有上限。调用者需持有锁。
func (s *scanShard) evict(now int64) {
	for k, b := range s.buckets {
		if b.refilled(now) >= scanBurst {
			delete(s.buckets, k)
		}
	}
	for k := range s.buckets {
		if len(s.buckets) < scanShardCap*3/4 {
			break
		}
		delete(s.buckets, k)
	}
}
