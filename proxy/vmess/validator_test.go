package vmess_test

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	. "github.com/xtls/xray-core/proxy/vmess"
)

func toAccount(a *Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func BenchmarkUserValidator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		v := NewTimedUserValidator()

		for j := 0; j < 1500; j++ {
			id := uuid.New()
			v.Add(&protocol.MemoryUser{
				Email: "test",
				Account: toAccount(&Account{
					Id: id.String(),
				}),
			})
		}

		common.Close(v)
	}
}

func TestRemoveByEmail(t *testing.T) {
	v := NewTimedUserValidator()
	users := map[string]*protocol.MemoryUser{}
	for i := range 200 {
		id := uuid.New()
		u := &protocol.MemoryUser{
			Email:   fmt.Sprintf("User-%d@Example.com", i),
			Account: toAccount(&Account{Id: id.String()}),
		}
		common.Must(v.Add(u))
		users[strings.ToLower(u.Email)] = u
	}
	r := rand.New(rand.NewPCG(3, 4))
	for range 120 {
		i := r.IntN(250) // some emails were never added
		email := fmt.Sprintf("user-%d@example.COM", i)
		_, want := users[strings.ToLower(email)]
		if got := v.Remove(email); got != want {
			t.Fatalf("Remove(%s) = %v, want %v", email, got, want)
		}
		delete(users, strings.ToLower(email))
	}
	if int(v.GetCount()) != len(users) {
		t.Fatalf("%d users left, want %d", v.GetCount(), len(users))
	}
	for _, u := range v.GetUsers() {
		if users[strings.ToLower(u.Email)] != u {
			t.Fatalf("unexpected user %s left", u.Email)
		}
	}
	for email := range users {
		if !v.Remove(email) {
			t.Fatalf("Remove(%s) of a remaining user failed", email)
		}
	}
	if v.GetCount() != 0 {
		t.Fatalf("%d users left after removing all", v.GetCount())
	}
}
