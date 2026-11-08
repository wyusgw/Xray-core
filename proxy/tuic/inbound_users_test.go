package tuic

import (
	"context"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func tuicUser(email string, id uuid.UUID) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: email, Account: &MemoryAccount{UUID: id, Password: "p"}}
}

func TestInboundUserEmailIndex(t *testing.T) {
	ctx := context.Background()
	in := &Inbound{}
	a, b := uuid.New(), uuid.New()
	in.AddUser(ctx, tuicUser("a", a))
	in.AddUser(ctx, tuicUser("b", b))

	if u := in.GetUser(ctx, "a"); u == nil || u.Email != "a" {
		t.Fatalf("GetUser(a) = %v", u)
	}
	if err := in.RemoveUser(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if in.GetUser(ctx, "a") != nil {
		t.Fatal("a still present")
	}
	if _, ok := in.userMap.Load(a); ok {
		t.Fatal("a's uuid still accepted")
	}
	if err := in.RemoveUser(ctx, "a"); err == nil {
		t.Fatal("removing a twice succeeded")
	}
	if in.GetUsersCount(ctx) != 1 {
		t.Fatalf("count = %d, want 1", in.GetUsersCount(ctx))
	}
}

func TestInboundReAddReplacesUUID(t *testing.T) {
	ctx := context.Background()
	in := &Inbound{}
	old, cur := uuid.New(), uuid.New()
	in.AddUser(ctx, tuicUser("a", old))
	in.AddUser(ctx, tuicUser("a", cur))
	if _, ok := in.userMap.Load(old); ok {
		t.Fatal("old uuid still accepted after re-adding the email")
	}
	if u := in.GetUser(ctx, "a"); u == nil || u.Account.(*MemoryAccount).UUID != cur {
		t.Fatalf("GetUser(a) = %v", u)
	}
}

func TestInboundRemoveKeepsUUIDTakenOver(t *testing.T) {
	ctx := context.Background()
	in := &Inbound{}
	id := uuid.New()
	in.AddUser(ctx, tuicUser("a", id))
	in.AddUser(ctx, tuicUser("b", id))
	in.RemoveUser(ctx, "a")
	if u := in.GetUser(ctx, "b"); u == nil {
		t.Fatal("removing a dropped b")
	}
}

func BenchmarkInboundRemoveUser(b *testing.B) {
	ctx := context.Background()
	in := &Inbound{}
	for i := 0; i < 10000; i++ {
		in.AddUser(ctx, tuicUser(fmt.Sprintf("user%d", i), uuid.New()))
	}
	id := uuid.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.AddUser(ctx, tuicUser("last", id))
		if err := in.RemoveUser(ctx, "last"); err != nil {
			b.Fatal(err)
		}
	}
}
