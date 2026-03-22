package authkit

import (
	"context"
	"testing"
)

func TestUserFromCtx_NilWhenAbsent(t *testing.T) {
	u := UserFromCtx(context.Background())
	if u != nil {
		t.Errorf("expected nil, got %+v", u)
	}
}

func TestUserFromCtx_ReturnsStoredUser(t *testing.T) {
	want := &User{Email: "alice@example.com", Role: "admin"}
	ctx := withUser(context.Background(), want)

	got := UserFromCtx(ctx)
	if got == nil {
		t.Fatal("expected non-nil user")
	}
	if got.Email != want.Email || got.Role != want.Role {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestUserFromCtx_ChildContextInherits(t *testing.T) {
	u := &User{Email: "bob@example.com"}
	parent := withUser(context.Background(), u)
	child, cancel := context.WithCancel(parent)
	defer cancel()

	got := UserFromCtx(child)
	if got == nil || got.Email != u.Email {
		t.Errorf("child context: got %v, want %v", got, u)
	}
}

func TestWithUser_DoesNotMutateParent(t *testing.T) {
	parent := context.Background()
	_ = withUser(parent, &User{Email: "x@example.com"})

	if UserFromCtx(parent) != nil {
		t.Error("withUser mutated the parent context")
	}
}
