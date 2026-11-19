package users

import (
	"testing"

	"github.com/google/uuid"
)

func TestSelfModificationRefused(t *testing.T) {
	me, other := uuid.New(), uuid.New()
	s := func(v string) *string { return &v }
	b := func(v bool) *bool { return &v }
	cases := []struct {
		name     string
		target   uuid.UUID
		role     *string
		disabled *bool
		want     bool
	}{
		{"demote self", me, s("user"), nil, true},
		{"disable self", me, nil, b(true), true},
		{"both on self", me, s("admin"), b(true), true},
		{"no-op on self", me, nil, nil, false},
		{"keep own admin role", me, s("admin"), nil, false},
		{"enable self (already enabled)", me, nil, b(false), false},
		{"demote other", other, s("user"), nil, false},
		{"disable other", other, nil, b(true), false},
	}
	for _, c := range cases {
		if got := selfModificationRefused(me, c.target, c.role, c.disabled); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
