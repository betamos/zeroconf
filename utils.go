package zeroconf

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var aLongTime = time.Hour * 24

var reDDD = regexp.MustCompile(`(\\\d\d\d)+`)

// Takes (part of) a domain string unpacked by dns and unescapes it back to its original string.
func unescapeDns(str string) string {
	str = reDDD.ReplaceAllStringFunc(str, unescapeDDD)
	return strings.ReplaceAll(str, `\`, ``)
}

// Takes an escaped \DDD+ string like `\226\128\153` and returns the escaped version `’`
// Note that escaping the same isn't necessary - it's handled by the lib.
//
// See https://github.com/miekg/dns/issues/1477
func unescapeDDD(ddd string) string {
	len := len(ddd) / 4
	p := make([]byte, len)
	for i := 0; i < len; i++ {
		off := i*4 + 1
		sub := ddd[off : off+3]
		n, _ := strconv.Atoi(sub)
		p[i] = byte(n)
	}
	// I guess we could substitue invalid utf8 chars here...
	return string(p)
}

// trimDot is used to trim the dots from the start or end of a string
func trimDot(s string) string {
	return strings.TrimRight(s, ".")
}

// Appends a suffix to a string if not already present
func ensureSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		return s
	}
	return s + suffix
}

// Returns the earliest of at least one times
func earliest(ts ...time.Time) time.Time {
	tMin := ts[0]
	for _, t := range ts {
		if t.Before(tMin) {
			tMin = t
		}
	}
	return tMin
}

type backoff struct {
	min, max time.Duration // min & max interval

	n            int // The current attempt
	lastInterval time.Duration
	next         time.Time // check with now.After(next), then
}

func newBackoff(min, max time.Duration) *backoff {
	return &backoff{min: min, max: max}
}

// Advances to next attempt if enough time has elapsed. Returns true if it succeeded.
func (b *backoff) advance(now time.Time) bool {
	if b.next.After(now) {
		return false
	}
	interval := time.Duration(float64(b.lastInterval) * float64(2.0+rand.Float64())) // 2-3 x
	interval = min(b.max, max(b.min, interval))
	b.next = now.Add(interval)
	b.lastInterval = interval
	b.n += 1
	return true
}

func (b *backoff) reset() {
	b.lastInterval = 0
	b.n = 0
	b.next = time.Time{}
}
