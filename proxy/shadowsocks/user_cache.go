package shadowsocks

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

const (
	relayDetectionThreshold = 6

	successUserTTL = 30 * time.Minute

	recentRebuildInterval = time.Second

	lruUpdateInterval = 5 * time.Second

	userCacheShards = 32
)

type UserCache struct {
	ipShards [userCacheShards]*userCacheShard
	recent   recentUsers
}

type recentUsers struct {
	users sync.Map // email -> *successUserEntry

	sorted     atomic.Pointer[[]*successUserEntry]
	builtAt    atomic.Int64
	rebuilding atomic.Bool
}

type successUserEntry struct {
	user       *protocol.MemoryUser
	lastAccess atomic.Int64 // UnixNano time of the last match
}

type userCacheShard struct {
	mu    sync.RWMutex
	cache map[string]*cacheEntry // client IP -> entry
	list  *cacheList
	cap   int
}

type cacheEntry struct {
	users      []*protocol.MemoryUser
	node       *cacheNode
	lastAccess int64 // UnixNano time of the last LRU update
	isRelay    bool
}

type cacheNode struct {
	key  string
	prev *cacheNode
	next *cacheNode
}

type cacheList struct {
	head *cacheNode
	tail *cacheNode
	size int
}

func NewUserCache(capacity int) *UserCache {
	if capacity <= 0 {
		capacity = 16384
	}
	shardCap := max(8, capacity/userCacheShards)

	c := &UserCache{}
	for i := range c.ipShards {
		c.ipShards[i] = &userCacheShard{
			cache: make(map[string]*cacheEntry, shardCap),
			list:  newCacheList(),
			cap:   shardCap,
		}
	}
	return c
}

func (c *UserCache) GetMultiUser(key string) []*protocol.MemoryUser {
	return c.getShard(key).getMultiUser(key)
}

func (c *UserCache) PutWithSuccess(key string, user *protocol.MemoryUser) {
	c.getShard(key).putMultiUser(key, user)
	c.recent.add(user)
}

func (c *UserCache) Remove(email string) {
	if email == "" {
		return
	}
	for _, s := range c.ipShards {
		s.removeByEmail(email)
	}
	c.recent.users.Delete(email)
}

// The snapshot is shared and lags; callers must not modify it and must recheck users.
func (c *UserCache) RecentUsers() []*successUserEntry {
	return c.recent.snapshot()
}

func (c *UserCache) getShard(key string) *userCacheShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = hash*31 + uint32(key[i])
	}
	return c.ipShards[hash%userCacheShards]
}

func (s *userCacheShard) getMultiUser(key string) []*protocol.MemoryUser {
	s.mu.RLock()
	entry, ok := s.cache[key]
	if !ok || entry.isRelay {
		s.mu.RUnlock()
		return nil
	}
	users := slices.Clone(entry.users)
	lastAccess := entry.lastAccess
	s.mu.RUnlock()

	now := time.Now().UnixNano()
	if now-lastAccess > int64(lruUpdateInterval) {
		s.mu.Lock()
		// Recheck after relocking: moving an evicted node would corrupt the list.
		if s.cache[key] == entry && now-entry.lastAccess > int64(lruUpdateInterval) {
			s.list.moveToFront(entry.node)
			entry.lastAccess = now
		}
		s.mu.Unlock()
	}
	return users
}

func (s *userCacheShard) putMultiUser(key string, user *protocol.MemoryUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixNano()

	if entry, ok := s.cache[key]; ok {
		if entry.isRelay {
			return
		}
		entry.lastAccess = now
		s.list.moveToFront(entry.node)
		for i, u := range entry.users {
			if u.Email != "" && u.Email == user.Email {
				entry.users[i] = user
				return
			}
		}
		entry.users = append(entry.users, user)
		if len(entry.users) > relayDetectionThreshold {
			entry.isRelay = true
			entry.users = nil
		}
		return
	}

	if s.list.size >= s.cap {
		if tail := s.list.removeTail(); tail != nil {
			delete(s.cache, tail.key)
		}
	}
	s.cache[key] = &cacheEntry{
		users:      []*protocol.MemoryUser{user},
		node:       s.list.addToFront(key),
		lastAccess: now,
	}
}

func (s *userCacheShard) removeByEmail(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, entry := range s.cache {
		entry.users = slices.DeleteFunc(entry.users, func(u *protocol.MemoryUser) bool {
			return u.Email == email
		})
		if len(entry.users) == 0 && !entry.isRelay {
			s.list.remove(entry.node)
			delete(s.cache, key)
		}
	}
}

func (r *recentUsers) add(user *protocol.MemoryUser) {
	if user.Email == "" {
		return
	}
	now := time.Now().UnixNano()
	if v, ok := r.users.Load(user.Email); ok {
		if entry := v.(*successUserEntry); entry.user == user {
			entry.lastAccess.Store(now)
			return
		}
		// Replace rather than modify: readers hold the entry without the lock.
	}
	entry := &successUserEntry{user: user}
	entry.lastAccess.Store(now)
	r.users.Store(user.Email, entry)
}

func (r *recentUsers) snapshot() []*successUserEntry {
	now := time.Now().UnixNano()
	snap := r.sorted.Load()
	if snap != nil && now-r.builtAt.Load() < int64(recentRebuildInterval) {
		return *snap
	}
	if !r.rebuilding.CompareAndSwap(false, true) {
		if snap != nil {
			return *snap
		}
		return nil
	}
	defer r.rebuilding.Store(false)

	// Sort on times read here so concurrent updates cannot break the comparison.
	type stamped struct {
		entry *successUserEntry
		at    int64
	}
	var live []stamped
	if snap != nil {
		live = make([]stamped, 0, len(*snap))
	}
	r.users.Range(func(key, value interface{}) bool {
		entry := value.(*successUserEntry)
		if at := entry.lastAccess.Load(); now-at > int64(successUserTTL) {
			r.users.CompareAndDelete(key, entry)
		} else {
			live = append(live, stamped{entry, at})
		}
		return true
	})
	slices.SortFunc(live, func(a, b stamped) int { return cmp.Compare(b.at, a.at) })
	list := make([]*successUserEntry, len(live))
	for i := range live {
		list[i] = live[i].entry
	}
	r.sorted.Store(&list)
	r.builtAt.Store(now)
	return list
}

func newCacheList() *cacheList {
	head := &cacheNode{}
	tail := &cacheNode{}
	head.next = tail
	tail.prev = head
	return &cacheList{head: head, tail: tail}
}

func (l *cacheList) addToFront(key string) *cacheNode {
	node := &cacheNode{key: key}
	l.insertFront(node)
	return node
}

func (l *cacheList) insertFront(node *cacheNode) {
	node.next = l.head.next
	node.prev = l.head
	l.head.next.prev = node
	l.head.next = node
	l.size++
}

func (l *cacheList) remove(node *cacheNode) {
	if node == nil || node == l.head || node == l.tail {
		return
	}
	node.prev.next = node.next
	node.next.prev = node.prev
	l.size--
}

func (l *cacheList) removeTail() *cacheNode {
	if l.size == 0 {
		return nil
	}
	node := l.tail.prev
	l.remove(node)
	return node
}

func (l *cacheList) moveToFront(node *cacheNode) {
	if node == nil || node == l.head.next {
		return
	}
	l.remove(node)
	l.insertFront(node)
}
