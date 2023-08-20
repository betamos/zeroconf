package zeroconf

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"time"
)

const (
	minInterval = 4 * time.Second
	maxInterval = time.Hour

	// TODO: Max time window to coalesce changes that occur simultaneously
	// maxCoalesceDuration = time.Millisecond * 25
)

// An operation that changes the state of the cache.
type Op int

const (
	// An instance was discovered.
	OpAdded Op = iota

	// An instance was updated, which contains the latest info, and all non-expired addrs.
	// An instance that keeps refreshing itself before expiry does not cause an update.
	OpUpdated

	// An instance expired or was intentionally removed. Note that there are no addrs with this op.
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

type Event struct {
	*Instance
	Op Op
}

func (e Event) String() string {
	return fmt.Sprintf("%v %v", e.Op, e.Instance)
}

// The cache maintains a map of service instances and notifies the user of changes.
// It relies on both the current time and query times in order to
// expire instances and inform when new queries are needed.
type cache struct {
	// map from instance name to a slice of "unique" instance records for the same instance,
	// in case there are multiple announcements. the "authoritative" record is the last one,
	// although other records can contain more addresses.
	//
	// invariant: slice sorted by lastSeen and always >= 1 element
	instances map[string][]*Instance
	cb        func(Event)
	maxAge    time.Duration

	// A number in range [0,1) used for query scheduling jitter. Regenerated at query time.
	entropy float64

	// Advanced by user
	lastQuery, now time.Time

	// The earliest expiry time of the instances in the cache.
	nextExpiry time.Time

	// The earliest live check scheduled, based on lastQuery and cache instances.
	// A live check query happens at 80-97% of an instance expiry. To prevent excessive
	// queries, only instances that responded to the last query are considered for a live check.
	nextLivecheck time.Time

	// Next periodic query, doubling based on lastQuery and capped at 60 min.
	nextPeriodic time.Time
}

// Create a new cache with an event callback. If maxTTL is non-zero, instances in the cache are capped
// to the provided duration in seconds.
func newCache(cb func(Event), maxAge time.Duration) *cache {
	return &cache{
		instances: make(map[string][]*Instance),
		//instances:  make(map[string]*Instance),
		cb:     cb,
		maxAge: maxAge,
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

func (c *cache) Put(i *Instance) {
	k := i.Name
	i.seenAt = c.now
	defer c.refresh()

	is := c.instances[i.Name]

	// Instance removed through a "Goodbye Packet"
	if i.ttl == 0 {
		// ...But check that we actually have it first
		if is != nil {
			i.Addrs = nil
			c.cb(Event{i, OpRemoved})
			delete(c.instances, k)
		}
		return
	}

	// Added instance
	if is == nil {
		last := *i
		last.Addrs = mergeAddrs(i) // Sort, for consistency
		c.cb(Event{&last, OpAdded})
		c.instances[k] = []*Instance{i}
		return
	}

	// Invariant: len(is) > 0, which means this is an update

	// Already "equal", simply update TTL without notifying the user
	if idx := slices.IndexFunc(is, i.Equal); idx > -1 {
		is[idx] = i
		slices.SortFunc(is, byLastSeen)
		return
	}

	// We assume this is a user-facing update
	last := *i
	last.Addrs = mergeAddrs(is...)
	c.instances[k] = append(is, i)
	c.cb(Event{&last, OpUpdated})

}

// Returns true if a query should be made right now. Remember to call `Queried()` after the
// query has been sent.
func (c *cache) ShouldQuery() bool {
	return c.nextPeriodic.Before(c.now) || c.nextLivecheck.Before(c.now)
}

// Should be called once a query has been made.
func (c *cache) Queried() {
	c.entropy = rand.Float64()

	// RFC6762 Section 5.2: [...] the interval between the first two queries MUST be at least one
	// second, the intervals between successive queries MUST increase by at least a factor of two.
	sinceLastQuery := c.now.Sub(c.lastQuery)
	interval := time.Duration(float64(sinceLastQuery) * float64(1.5+c.entropy)) // 1.5 - 2.5x
	if interval < minInterval {
		interval = minInterval
	} else if interval > maxInterval {
		interval = maxInterval
	}
	c.lastQuery = c.now
	c.nextPeriodic = c.now.Add(interval)
	c.refresh()
}

// Returns the time for the next event, either a query or cache expiry
func (c *cache) NextDeadline() time.Time {
	soonest := c.nextPeriodic
	if c.nextExpiry.Before(soonest) {
		soonest = c.nextExpiry
	}
	if c.nextLivecheck.Before(soonest) {
		soonest = c.nextLivecheck
	}
	return soonest
}

// Recalculates nextExpiry and nextLivecheck
func (c *cache) refresh() {
	// Use maxInterval simply for a large time value
	c.nextExpiry, c.nextLivecheck = c.now.Add(maxInterval), c.now.Add(maxInterval)
	for k, is := range c.instances {

		// Copy the last instance as authoritative as template for updates etc
		last := *is[len(is)-1]

		// Inferred ttl
		ttl := min(c.maxAge, time.Second*time.Duration(last.ttl))

		// If there are expired entries, update list and trigger an update
		if n := expired(is, c.now, ttl); n > 0 {
			is = is[n:]
			last.Addrs = mergeAddrs(is...) // Remaining valid addresses, possibly empty

			// All entries expired, so we remove
			if len(is) == 0 {
				delete(c.instances, k)
				c.cb(Event{&last, OpRemoved})
				continue
			}

			// Some entries remain, so we update

			// Modifying a map entry during iteration is totally kosher but Go spec insists on
			// making that hard to find because "it's too obvious"... Well
			c.instances[k] = is
			c.cb(Event{&last, OpUpdated})
		}

		// Use the first entry to update next expiry
		firstExpiry := is[0].seenAt.Add(ttl)
		if firstExpiry.Before(c.nextExpiry) {
			c.nextExpiry = firstExpiry
		}

		// An instance has already been queried if it hasn't been seen since the last query
		if is[0].seenAt.Before(c.lastQuery) {
			continue
		}

		// Update next livecheck
		floatDur := float64(ttl) * (0.80 + c.entropy*0.17) // 80-97% of ttl
		liveCheck := is[0].seenAt.Add(time.Duration(floatDur))
		if liveCheck.Before(c.nextLivecheck) {
			c.nextLivecheck = liveCheck
		}
	}
}

// Return sorted, distinct addrs from a number of instances
func mergeAddrs(is ...*Instance) (addrs []netip.Addr) {
	for _, i := range is {
		addrs = append(addrs, i.Addrs...)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	slices.Compact(addrs)
	return
}

// Returns the number of expired entries
func expired(is []*Instance, now time.Time, ttl time.Duration) (n int) {
	for _, i := range is {
		// If expired, remove instantly
		expiry := i.seenAt.Add(ttl)
		if expiry.After(now) { // no more expired entries
			break
		}
		n++
	}
	return n
}

func byLastSeen(a *Instance, b *Instance) int {
	return int(a.seenAt.Sub(b.seenAt))
}
