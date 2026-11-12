package shadowsocks

import (
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

const (
	retiredUserTTL  = 7 * 24 * time.Hour
	maxRetiredUsers = 10000
)

// retiredUsers is guarded by the Validator lock.
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
