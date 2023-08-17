package zeroconf

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sleep with cancelation
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	return ctx.Err()
}

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
