package account

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func newUser(email, auth string) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: email, Account: &MemoryAccount{Auth: auth}}
}

func TestValidatorEmailIndex(t *testing.T) {
	v := NewValidator()
	v.Add(newUser("a", "auth-a"))
	v.Add(newUser("b", "e8c1f2a4-0d1b-4c2e-9f3a-1b2c3d4e5f60"))

	if u := v.GetByEmail("a"); u == nil || u.Email != "a" {
		t.Fatalf("GetByEmail(a) = %v", u)
	}
	if u := v.Get("e8c1f2a4-0d1b-4c2e-9f3a-1b2c3d4e5f60"); u == nil || u.Email != "b" {
		t.Fatalf("Get(uuid auth) = %v", u)
	}

	v.DelByEmail("b")
	if v.GetByEmail("b") != nil || v.Get("e8c1f2a4-0d1b-4c2e-9f3a-1b2c3d4e5f60") != nil {
		t.Fatal("b still present after DelByEmail")
	}
	if v.GetCount() != 1 {
		t.Fatalf("count = %d, want 1", v.GetCount())
	}
}

func TestValidatorReAddReplacesAuth(t *testing.T) {
	v := NewValidator()
	v.Add(newUser("a", "old"))
	v.Add(newUser("a", "new"))
	if v.Get("old") != nil {
		t.Fatal("old auth still valid after re-adding the email")
	}
	if u := v.GetByEmail("a"); u == nil || u.Account.(*MemoryAccount).Auth != "new" {
		t.Fatalf("GetByEmail(a) = %v", u)
	}
	v.DelByEmail("a")
	if v.NotEmpty() {
		t.Fatal("validator not empty")
	}
}

func TestValidatorDelKeepsAuthTakenOver(t *testing.T) {
	v := NewValidator()
	v.Add(newUser("a", "shared"))
	v.Add(newUser("b", "shared"))
	v.DelByEmail("a")
	if u := v.Get("shared"); u == nil || u.Email != "b" {
		t.Fatalf("removing a dropped b's auth: %v", u)
	}
}

func TestValidatorEmptyEmail(t *testing.T) {
	v := NewValidator()
	v.Add(newUser("", "anon"))
	if v.GetByEmail("") == nil {
		t.Fatal("user without email not found")
	}
	v.DelByEmail("")
	if v.NotEmpty() {
		t.Fatal("user without email not removed")
	}
}

func BenchmarkValidatorDelByEmail(b *testing.B) {
	v := NewValidator()
	for i := 0; i < 10000; i++ {
		v.Add(newUser(fmt.Sprintf("user%d", i), fmt.Sprintf("auth%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.DelByEmail("user9999")
		v.Add(newUser("user9999", "auth9999"))
	}
}
