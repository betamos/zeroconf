package zeroconf

import (
	"context"
	"strings"
	"time"
)

func parseSubtypes(service string) (string, []string) {
	subtypes := strings.Split(service, ",")
	return subtypes[0], subtypes[1:]
}

// trimDot is used to trim the dots from the start or end of a string
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

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
