package zeroconf

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"time"
)

// A state change operation.
type Op int

const (
	// A service was added.
	OpAdded Op = iota

	// A previously added service is updated, e.g. with a new set of addrs.
	// Note that regular TTL refreshes do not trigger updates.
	OpUpdated

	// A service expired or was unannounced. There are no addresses associated with this op.
	OpRemoved
)

func (op Op) String() string {
	switch op {
	case OpAdded:
		return "[+]"
	case OpUpdated:
		return "[~]"
	case OpRemoved:
		return "[-]"
	default:
		return "[?]"
	}
}

// An event represents a change in the state of a service, identified by its name.
// The service reflects the new state and is always non-nil. If a service is found on multiple
// network interfaces with different addresses, they are merged and reflected as updates according
// to their individual life cycles.
type Event struct {
	*Service
	Op
}

func (e Event) String() string {
	return fmt.Sprintf("%v %v", e.Op, e.Service)
}

// The cache maintains a map of services and notifies the user of changes.
// It relies on both the current time and query times in order to
// expire services and inform when new queries are needed.
// The cache should use wall-clock time and will automatically adjust for unexpected jumps
// backwards in time.
type cache struct {
	// map from service name to a list of services with the same identity, but that may have
	// different expiry, addrs etc.
	// The "authoritative" record for most fields is the last one, but all unexpired addrs are
	// merged into a single "presentable" record for dispatched events.
	//
	// invariant: slice sorted by seenAt and always >= 1 element
	services map[string][]*Service
	cb       func(Event)

	// A number in range [0,1) used for query scheduling jitter. Constant, to simplify the dance
	// between scheduling and completing tasks.
	entropy float64

	// Advanced by user
	lastQuery, lastRefresh, now time.Time

	// The earliest expiry time of the services in the cache.
	nextExpiry time.Time

	// The earliest live check scheduled, based on lastQuery and cache services.
	// A live check query happens at 80-97% of a service expiry. To prevent excessive
	// queries, only services that responded to the last query are considered for a live check.
	nextLivecheck time.Time
}

// Create a new cache with an event callback. If maxTTL is non-zero, services in the cache are capped
// to the provided duration in seconds.
func newCache(cb func(Event)) *cache {
	return &cache{
		services: make(map[string][]*Service),
		cb:       cb,
		entropy:  rand.Float64(),
	}
}

// Puts an entry and bumps the current time. No events are dispatched until advanced.
func (c *cache) Put(svc *Service, now time.Time) {
	c.setNow(now)
	k := svc.String()
	svc.seenAt = c.now
	c.services[k] = append(c.services[k], svc)
}

func (c *cache) setNow(now time.Time) {
	if !now.After(c.now) {
		// Time jumped backwards. Increment instead to preserve causality while we wait for
		// the clock to sync up. Existing expiries will be delayed, but this amount should be
		// miniscule.
		now = c.now.Add(1)
	}
	c.now = now
}

// Advances the state of the cache, and dispatches new events.
// Returns true if a query should be made right now. Remember to call `Queried()` after the
// query has been sent.
func (c *cache) Advance(now time.Time) (shouldQuery bool) {
	c.setNow(now)
	c.refresh()
	return c.nextLivecheck.Before(c.now)
}

// Should be called once a query has been made.
func (c *cache) Queried() {
	// RFC6762 Section 5.2: [...] the interval between the first two queries MUST be at least one
	// second, the intervals between successive queries MUST increase by at least a factor of two.
	c.lastQuery = c.now
	c.refresh()
}

// Returns the time for the next event, either a query or cache expiry
func (c *cache) NextDeadline() time.Time {
	return earliest(c.nextLivecheck, c.nextExpiry)
}

// Recalculates nextExpiry and nextLivecheck
func (c *cache) refresh() {
	c.nextExpiry, c.nextLivecheck = c.now.Add(aLongTime), c.now.Add(aLongTime)
	for k := range c.services {

		merged := c.refreshService(k)
		if merged == nil {
			continue // The service no longer exists
		}

		// Use the first service to update next expiry
		firstExpiry := merged.seenAt.Add(merged.ttl)
		if firstExpiry.Before(c.nextExpiry) {
			c.nextExpiry = firstExpiry
		}
		// Update next livecheck

		// RFC6762 Section 5.2: The querier should plan to issue a query at 80% of the record
		// lifetime, and then if no answer is received, at 85%, 90%, and 95%. [...]
		// a random variation of 2% of the record TTL should be added
		for _, percentile := range []float64{.80, .85, 0.90, 0.95} {
			// invariant: liveCheck increasing with each iteration
			floatDur := float64(merged.ttl) * (percentile + c.entropy*0.02) // 80-97% of ttl
			liveCheck := merged.seenAt.Add(time.Duration(floatDur))

			// nextLivecheck is earlier than current candidate, so neither this nor later
			// iterations can reduce it further, hence break out
			if liveCheck.After(c.nextLivecheck) {
				break
			}
			// invariant: liveCheck (candidate) is earlier and a valid candidate

			// if this candidate livecheck comes after last query, we're in the right bracket.
			if c.lastQuery.Before(liveCheck) {
				c.nextLivecheck = liveCheck
				break
			}
			// otherwise, we have already checked it and continue with the next percentile
		}
	}
	c.lastRefresh = c.now
}

// Refreshes the records of a specific service.
// Dispoatches events for records added or removed between last refresh and now.
// Returns the merged service, or nil if there are no more records remaining.
func (c *cache) refreshService(k string) *Service {
	svcs := c.services[k]
	last := template(svcs[len(svcs)-1])
	expiryCutoff := c.now.Add(-last.ttl)

	var lastIdx, expiredIdx = -1, -1
	for idx, svc := range svcs {
		if svc.seenAt.Before(c.lastRefresh) {
			lastIdx = idx
		}

		if svc.seenAt.Before(expiryCutoff) {
			expiredIdx = idx
		}
	}

	// The set of services before last refresh
	oldSvcs := svcs[:lastIdx+1]

	// The set of services now (may overlap with the old set)
	svcs = compact(svcs[expiredIdx+1:])

	// There are no remaining entries
	if len(svcs) == 0 {
		delete(c.services, k)

		// Sanity: only remove a service that existed previously.
		// The template will reflect the "goodbye" record, without addrs
		if len(oldSvcs) > 0 {
			c.cb(Event{last, OpRemoved})
		}
		return nil
	}

	// Invariant: svcs > 1, do a proper merge
	c.services[k] = svcs
	merged := mergeRecords(svcs...)

	// Added if no old services, otherwise full comparison
	if len(oldSvcs) == 0 {
		c.cb(Event{merged, OpAdded})
	} else if old := mergeRecords(oldSvcs...); !old.deepEqual(merged) {
		c.cb(Event{merged, OpUpdated})
	}
	return merged
}

// Return a merged service entry with the union of all addrs. The merged service assumes the
// earliest seenAt (for livechecks) and the ttl of the latest entry. The list must be
// sorted by seenAt.
func mergeRecords(svcs ...*Service) *Service {
	merged := template(svcs[len(svcs)-1]) // Copy fields from the last record
	merged.seenAt = svcs[0].seenAt        // Except seenAt, which should be earliest
	for _, svc := range svcs {
		merged.Addrs = append(merged.Addrs, svc.Addrs...)
	}
	slices.SortFunc(merged.Addrs, netip.Addr.Compare)
	merged.Addrs = slices.Compact(merged.Addrs)
	return merged
}

// Compacts a list of services, removes duplicates.
func compact(svcs []*Service) (comp []*Service) {
	// Populated as addrs are added
	addrMap := make(map[netip.Addr]bool)

	// Reverse iteration to populate the latest first
	for i := len(svcs) - 1; i >= 0; i-- {
		svc := svcs[i]
		var addrs []netip.Addr

		// Only add if not already previously added
		for _, addr := range svc.Addrs {
			if !addrMap[addr] {
				addrMap[addr] = true
				addrs = append(addrs, addr)
			}
		}
		// The last record is always added
		if len(addrs) > 0 || i == len(svcs)-1 {
			svc = template(svc)
			svc.Addrs = addrs
			comp = append(comp, svc)
		}
	}
	slices.Reverse(comp) // Restore order
	return
}

// Create a template service from an entry, without addrs.
func template(svc *Service) *Service {
	new := *svc
	new.Addrs = nil
	return &new
}
