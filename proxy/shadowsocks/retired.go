package shadowsocks

import (
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

const (
	// How long the key of a removed user is kept.
	retiredUserTTL = 7 * 24 * time.Hour
	// Keys of removed users kept at most.
	maxRetiredUsers = 10000
)

// retiredUsers keeps the keys of removed users. Most requests that match no
// user come from clients of expired users that keep reconnecting. Matching
// them against these keys tells them apart from other failures, so they can
// be rejected cheaply without limiting other clients behind the same IP.
//
// It is guarded by the Validator lock.
type retiredUsers struct {
	byKey map[string]*retiredUser
	list  []*retiredUser // oldest first, may hold dropped entries
}

type retiredUser struct {
	user    *protocol.MemoryUser
	at      int64 // UnixNano time of removal
	dropped bool
}

func retiredKey(u *protocol.MemoryUser) (string, bool) {
	account, ok := u.Account.(*MemoryAccount)
	if !ok || !account.Cipher.IsAEAD() {
		return "", false
	}
	return string(account.Key), true
}

// add records that u was removed.
func (r *retiredUsers) add(u *protocol.MemoryUser, now time.Time) {
	key, ok := retiredKey(u)
	if !ok {
		return
	}
	if r.byKey == nil {
		r.byKey = make(map[string]*retiredUser)
	}
	if old := r.byKey[key]; old != nil {
		old.dropped = true
	}
	e := &retiredUser{user: u, at: now.UnixNano()}
	r.byKey[key] = e
	r.list = append(r.list, e)
	r.prune(now)
}

// remove forgets the removed user with the same key as u, which is in use
// again.
func (r *retiredUsers) remove(u *protocol.MemoryUser) {
	key, ok := retiredKey(u)
	if !ok {
		return
	}
	if e := r.byKey[key]; e != nil {
		e.dropped = true
		delete(r.byKey, key)
	}
}

// contains reports whether u is still a removed user.
func (r *retiredUsers) contains(u *protocol.MemoryUser) bool {
	key, ok := retiredKey(u)
	if !ok {
		return false
	}
	e := r.byKey[key]
	return e != nil && e.user == u
}

func (r *retiredUsers) prune(now time.Time) {
	expired := now.Add(-retiredUserTTL).UnixNano()
	i := 0
	for ; i < len(r.list); i++ {
		e := r.list[i]
		if !e.dropped && e.at >= expired && len(r.byKey) <= maxRetiredUsers {
			break
		}
		if !e.dropped {
			e.dropped = true
			delete(r.byKey, string(e.user.Account.(*MemoryAccount).Key))
		}
	}
	r.list = r.list[i:]
	if len(r.list) > 2*len(r.byKey)+64 {
		live := make([]*retiredUser, 0, len(r.byKey))
		for _, e := range r.list {
			if !e.dropped {
				live = append(live, e)
			}
		}
		r.list = live
	}
}

// match returns the removed user whose key opens the request, if any.
func (r *retiredUsers) match(t *trialDecrypter, now time.Time) *protocol.MemoryUser {
	expired := now.Add(-retiredUserTTL).UnixNano()
	for i := len(r.list) - 1; i >= 0; i-- {
		e := r.list[i]
		if e.dropped || e.at < expired {
			continue
		}
		if t.try(e.user) {
			return e.user
		}
	}
	return nil
}
