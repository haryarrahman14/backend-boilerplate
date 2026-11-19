package ratelimit

import (
	"testing"
	"time"
)

func TestFixedWindow(t *testing.T) {
	l := New(3, time.Minute)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := range 3 {
		if ok, _ := l.Allow("1.2.3.4", t0.Add(time.Duration(i)*time.Second)); !ok {
			t.Fatalf("hit %d should be allowed", i+1)
		}
	}
	ok, retry := l.Allow("1.2.3.4", t0.Add(10*time.Second))
	if ok {
		t.Fatal("4th hit in the window must be rejected")
	}
	if retry != 50*time.Second {
		t.Fatalf("retry = %v, want 50s (time left in the window)", retry)
	}

	if ok, _ := l.Allow("5.6.7.8", t0.Add(10*time.Second)); !ok {
		t.Fatal("other keys have their own budget")
	}

	if ok, _ := l.Allow("1.2.3.4", t0.Add(59*time.Second+999*time.Millisecond)); ok {
		t.Fatal("still inside the window")
	}
	if ok, _ := l.Allow("1.2.3.4", t0.Add(time.Minute)); !ok {
		t.Fatal("a new window starts after the period")
	}
}

func TestSweepDropsExpiredWindows(t *testing.T) {
	l := New(1, time.Minute)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Allow("a", t0)
	l.Allow("b", t0)
	l.Allow("c", t0.Add(2*time.Minute))
	if len(l.windows) != 1 {
		t.Fatalf("expired windows not swept: %d left", len(l.windows))
	}
}

func TestMapCap(t *testing.T) {
	l := New(5, time.Minute)
	l.maxKeys = 2
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Allow("a", t0)
	l.Allow("b", t0)
	for range 10 {
		if ok, _ := l.Allow("c", t0.Add(time.Second)); !ok {
			t.Fatal("a new key while the map is full must be allowed")
		}
	}
	if _, tracked := l.windows["c"]; tracked || len(l.windows) != 2 {
		t.Fatal("a new key while the map is full must not be tracked")
	}
	for range 4 {
		l.Allow("a", t0.Add(time.Second))
	}
	if ok, _ := l.Allow("a", t0.Add(time.Second)); ok {
		t.Fatal("existing keys stay limited while the map is full")
	}
	l.Allow("c", t0.Add(time.Minute))
	if _, tracked := l.windows["c"]; !tracked {
		t.Fatal("after the window the sweep frees space and new keys are tracked again")
	}
}

func TestKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":          "203.0.113.9",
		"::ffff:203.0.113.9":   "203.0.113.9",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"":                     "",
	} {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}
