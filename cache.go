package zeroconf

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"time"
)

// TODO: Max time window to coalesce changes that occur simultaneously
// maxCoalesceDuration = time.Millisecond * 25

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
	// map from service name to a slice of "distinct" records,
	// in case there are multiple announcements. the "authoritative" record is the last one,
	// although other records can contain more addresses.
	//
	// invariant: slice sorted by lastSeen and always >= 1 element
	services map[string][]*Service
	cb       func(Event)

	// A number in range [0,1) used for query scheduling jitter. Regenerated at query time.
	entropy float64

	// Advanced by user
	lastQuery, now time.Time

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
	}
}

// Advances the current time. Should be called before other methods.
func (c *cache) Advance(now time.Time) {
	c.now = now
	if c.now.Before(c.nextExpiry) {
		return
	}
	c.refresh()
}

func (c *cache) Put(svc *Service) {
	k := svc.String()
	svc.seenAt = c.now
	defer c.refresh()

	svcs := c.services[k]

	// Service removed through a "Goodbye Packet"
	if svc.ttl == 0 {
		// ...But check that we actually have it first
		if svcs != nil {
			svc.Addrs = nil
			c.cb(Event{svc, OpRemoved})
			delete(c.services, k)
		}
		return
	}

	// Added service
	if svcs == nil {
		last := *svc
		last.Addrs = mergeAddrs(svc) // Sort, for consistency
		c.cb(Event{&last, OpAdded})
		c.services[k] = []*Service{svc}
		return
	}

	// Invariant: len(is) > 0, which means this is an update

	// Already "equal", simply update TTL without notifying the user
	if idx := slices.IndexFunc(svcs, svc.deepEqual); idx > -1 {
		svcs[idx] = svc
		slices.SortFunc(svcs, byLastSeen)
		return
	}

	// We assume this is a user-facing update
	svcs = append(svcs, svc)
	last := *svc
	last.Addrs = mergeAddrs(svcs...)
	c.services[k] = svcs
	c.cb(Event{&last, OpUpdated})

}

// Returns true if a query should be made right now. Remember to call `Queried()` after the
// query has been sent.
func (c *cache) ShouldQuery() bool {
	return c.nextLivecheck.Before(c.now)
}

// Should be called once a query has been made.
func (c *cache) Queried() {
	c.entropy = rand.Float64()

	// RFC6762 Section 5.2: [...] the interval between the first two queries MUST be at least one
	// second, the intervals between successive queries MUST increase by at least a factor of two.
	c.lastQuery = c.now
	c.refresh()
}

// Returns the time for the next event, either a query or cache expiry
func (c *cache) NextDeadline() time.Time {
	if c.nextLivecheck.Before(c.nextExpiry) {
		return c.nextLivecheck
	}
	return c.nextExpiry
}

// Recalculates nextExpiry and nextLivecheck
func (c *cache) refresh() {
	// Use maxInterval simply for a large time value
	c.nextExpiry, c.nextLivecheck = c.now.Add(maxInterval), c.now.Add(maxInterval)
	for k, svcs := range c.services {

		// Copy the last service as authoritative as template for updates etc
		last := *svcs[len(svcs)-1]

		// If there are expired services, update list and trigger an update
		if n := expired(svcs, c.now, last.ttl); n > 0 {
			svcs = svcs[n:]
			last.Addrs = mergeAddrs(svcs...) // Remaining valid addresses, possibly empty

			// All services expired, so we remove
			if len(svcs) == 0 {
				delete(c.services, k)
				c.cb(Event{&last, OpRemoved})
				continue
			}

			// Some services remain, so we update

			// Modifying a map entry during iteration is totally kosher but Go spec insists on
			// making that hard to find because "it's too obvious"... Well
			c.services[k] = svcs
			c.cb(Event{&last, OpUpdated})
		}

		// Use the first service to update next expiry
		firstExpiry := svcs[0].seenAt.Add(last.ttl)
		if firstExpiry.Before(c.nextExpiry) {
			c.nextExpiry = firstExpiry
		}

		// An service has already been queried if it hasn't been seen since the last query
		if svcs[0].seenAt.Before(c.lastQuery) {
			continue
		}

		// Update next livecheck
		floatDur := float64(last.ttl) * (0.80 + c.entropy*0.17) // 80-97% of ttl
		liveCheck := svcs[0].seenAt.Add(time.Duration(floatDur))
		if liveCheck.Before(c.nextLivecheck) {
			c.nextLivecheck = liveCheck
		}
	}
}

// Return sorted, distinct addrs from a number of services
func mergeAddrs(svcs ...*Service) (addrs []netip.Addr) {
	for _, svc := range svcs {
		addrs = append(addrs, svc.Addrs...)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

// Returns the number of expired services.
// While we're at it, adjust for unexpected time jumps.
func expired(svcs []*Service, now time.Time, ttl time.Duration) (n int) {
	for _, svc := range svcs {
		// Ensure that seenAt is before now (in the rare case wall time jumped backwards)
		if svc.seenAt.After(now) {
			svc.seenAt = now
		}
		// If expired, remove instantly
		expiry := svc.seenAt.Add(ttl)
		if expiry.Before(now) { // no more expired entries
			n++
		}
	}
	return n
}

func byLastSeen(a *Service, b *Service) int {
	return int(a.seenAt.Sub(b.seenAt))
}
