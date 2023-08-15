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
