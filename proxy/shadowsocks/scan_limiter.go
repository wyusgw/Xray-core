package shadowsocks

import (
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

// scanLimiter limits per source IP the full scans that match nobody, so other clients
// behind a relay are unaffected; a throttled IP only tries cached and recent users.
const (
	scanLimitMinUsers = 256

	scanBurst  = 8
	scanRefill = 2 * time.Second

	scanLimitedRecentUsers = 64

	scanShards      = 32
	scanShardCap    = 4096
	maxRetiredPerIP = 32
)

type scanBucket struct {
	tokens float64
	last   int64 // UnixNano time of tokens

	retired []*protocol.MemoryUser
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

func (b *scanBucket) refilled(now int64) float64 {
	t := b.tokens + float64(now-b.last)/float64(scanRefill)
	if t > scanBurst {
		t = scanBurst
	}
	return t
}

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

func (l *scanLimiter) Fail(key string) {
	if key == "" {
		return
	}
	now := time.Now().UnixNano()
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucket(key, now)
	b.tokens = b.refilled(now) - 1
	if b.tokens < 0 {
		b.tokens = 0
	}
	b.last = now
}

func (l *scanLimiter) Success(key string) {
	if key == "" {
		return
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		return
	}
	if len(b.retired) == 0 {
		delete(s.buckets, key)
		return
	}
	b.tokens = scanBurst // keep the removed users for other clients of the IP
}

func (l *scanLimiter) Retired(key string) []*protocol.MemoryUser {
	if key == "" {
		return nil
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[key]; ok && len(b.retired) > 0 {
		return slices.Clone(b.retired)
	}
	return nil
}

func (l *scanLimiter) AddRetired(key string, u *protocol.MemoryUser) {
	if key == "" {
		return
	}
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucket(key, time.Now().UnixNano())
	b.retired = slices.DeleteFunc(b.retired, func(r *protocol.MemoryUser) bool { return r == u })
	if len(b.retired) >= maxRetiredPerIP {
		b.retired = slices.Delete(b.retired, 0, len(b.retired)-maxRetiredPerIP+1)
	}
	b.retired = append(b.retired, u)
}

func (l *scanLimiter) DropRetired(key string, u *protocol.MemoryUser) {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[key]; ok {
		b.retired = slices.DeleteFunc(b.retired, func(r *protocol.MemoryUser) bool { return r == u })
	}
}

// bucket must be called with s.mu held.
func (s *scanShard) bucket(key string, now int64) *scanBucket {
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) >= scanShardCap {
			s.evict(now)
		}
		b = &scanBucket{tokens: scanBurst, last: now}
		s.buckets[key] = b
	}
	return b
}

// evict must be called with s.mu held.
func (s *scanShard) evict(now int64) {
	for k, b := range s.buckets {
		if b.refilled(now) >= scanBurst && len(b.retired) == 0 {
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
