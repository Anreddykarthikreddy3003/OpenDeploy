package cronexpr

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04 Mon", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestMatches(t *testing.T) {
	cases := []struct {
		expr string
		t    string
		want bool
	}{
		{"*/15 * * * *", "2026-09-28 10:30 Mon", true},
		{"*/15 * * * *", "2026-09-28 10:31 Mon", false},
		{"5/15 * * * *", "2026-09-28 10:20 Mon", true},
		{"5/15 * * * *", "2026-09-28 10:15 Mon", false},
		{"0 9-17 * * 1-5", "2026-09-28 09:00 Mon", true},
		{"0 9-17 * * 1-5", "2026-09-27 09:00 Sun", false},
		{"@daily", "2026-09-28 00:00 Mon", true},
		{"@hourly", "2026-09-28 13:00 Mon", true},
		{"0 0 1 * *", "2026-10-01 00:00 Thu", true},
		{"0 0 13 * 5", "2026-11-13 00:00 Fri", true}, // dom OR dow
		{"0 0 13 * 5", "2026-11-06 00:00 Fri", true},
		{"0 0 * * 7", "2026-09-27 00:00 Sun", true}, // 7 == Sunday
		{"30 2 * * *", "2026-09-28 02:30 Mon", true},
	}
	for _, c := range cases {
		s, err := Parse(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := s.Matches(at(c.t)); got != c.want {
			t.Errorf("%s at %s = %v", c.expr, c.t, got)
		}
	}
}

func TestInvalid(t *testing.T) {
	for _, e := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "*/0 * * * *", "a b c d e", "5-1 * * * *", "* * 0 * *"} {
		if _, err := Parse(e); err == nil {
			t.Errorf("%q accepted", e)
		}
	}
}
