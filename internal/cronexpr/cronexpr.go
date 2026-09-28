// Package cronexpr parses standard 5-field cron expressions (lists, ranges,
// steps and @aliases) for opendeploy.yaml cron jobs.
package cronexpr

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed 5-field cron expression.
type Schedule struct {
	min, hour, dom, month, dow uint64 // bitsets
	domStar, dowStar           bool
}

var cronAliases = map[string]string{
	"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0",
	"@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *",
}

// ParseSchedule parses standard cron syntax (lists, ranges, steps, aliases).
func Parse(expr string) (*Schedule, error) {
	expr = strings.TrimSpace(expr)
	if a, ok := cronAliases[expr]; ok {
		expr = a
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("cron: expected 5 fields in %q", expr)
	}
	var s Schedule
	var err error
	if s.min, err = parseField(f[0], 0, 59); err != nil {
		return nil, err
	}
	if s.hour, err = parseField(f[1], 0, 23); err != nil {
		return nil, err
	}
	if s.dom, err = parseField(f[2], 1, 31); err != nil {
		return nil, err
	}
	if s.month, err = parseField(f[3], 1, 12); err != nil {
		return nil, err
	}
	if s.dow, err = parseField(strings.ReplaceAll(f[4], "7", "0"), 0, 6); err != nil {
		return nil, err
	}
	s.domStar, s.dowStar = f[2] == "*", f[4] == "*"
	return &s, nil
}

func parseField(f string, lo, hi int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(f, ",") {
		step, hasStep := 1, false
		if base, st, ok := strings.Cut(part, "/"); ok {
			hasStep = true
			n, err := strconv.Atoi(st)
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("cron: bad step %q", part)
			}
			step, part = n, base
		}
		a, b := lo, hi
		if part != "*" {
			if x, y, ok := strings.Cut(part, "-"); ok {
				var e1, e2 error
				a, e1 = strconv.Atoi(x)
				b, e2 = strconv.Atoi(y)
				if e1 != nil || e2 != nil {
					return 0, fmt.Errorf("cron: bad range %q", part)
				}
			} else {
				n, err := strconv.Atoi(part)
				if err != nil {
					return 0, fmt.Errorf("cron: bad value %q", part)
				}
				a, b = n, n
				if hasStep {
					b = hi
				}
			}
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("cron: %q out of range %d-%d", part, lo, hi)
		}
		for i := a; i <= b; i += step {
			bits |= 1 << uint(i)
		}
	}
	return bits, nil
}

// Matches reports whether t (minute resolution) is scheduled.
func (s *Schedule) Matches(t time.Time) bool {
	if s.min&(1<<uint(t.Minute())) == 0 || s.hour&(1<<uint(t.Hour())) == 0 || s.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	domOK := s.dom&(1<<uint(t.Day())) != 0
	dowOK := s.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dowOK
	case s.dowStar:
		return domOK
	default:
		return domOK || dowOK // standard cron semantics
	}
}
