package zeroconf

import (
	"time"
)

const (
	minInterval = 4 * time.Second
	maxInterval = time.Hour
)

// An operation on the state of the cache.
type Op int

func (op Op) String() string {
	switch op {
	case OpAdded:
		return "OpAdded"
	case OpRemoved:
		return "OpRemoved"
	default:
		return "<OpUnknown>"
	}
}

const (
	// A service was discovered.
	OpAdded Op = iota

	// A service expired or was intentionally removed.
	OpRemoved
)

// An event consists of an operation and a service entry.
type Event struct {
	*ServiceEntry
	Op Op
}

// The cache maintains a map of service entries and notifies the user of changes.
// It relies on both the current time and query times in order to
// expire entries and inform when new queries are needed.
type cache struct {
	entries map[string]*ServiceEntry
	events  chan<- Event
	maxTTL  uint32

	// Advanced by user
	lastQuery, now time.Time

	// The earliest expiry time of the entries in the cache.
	nextExpiry time.Time

	// The earliest live check scheduled, based on lastQuery and cache entries.
	// A live check query happens at 80-95% of an entry expiry. To prevent excessive
	// queries, only entries that responded to the last query are considered for a live check.
	nextLivecheck time.Time

	// Next periodic query, doubling based on lastQuery and capped at 60 min.
	nextPeriodic time.Time
}

// Create a new cache with an event channel. If maxTTL is non-zero, entries in the cache are capped
// to the provided duration in seconds.
func newCache(events chan<- Event, maxTTL uint32) *cache {
	return &cache{
		entries: make(map[string]*ServiceEntry),
		events:  events,
		maxTTL:  maxTTL,
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

func (c *cache) Put(id string, entry *ServiceEntry) {
	entry.seenAt = c.now
	if entry.TTL == 0 {
		// Existing entry removed through a "Goodbye Packet"
		if _, ok := c.entries[id]; ok {
			c.events <- Event{entry, OpRemoved}
		}
		delete(c.entries, id)
	} else if _, ok := c.entries[id]; ok {
		// Existing entry extended, suppress duplicates
		// TODO: Compare and send updates.
		c.entries[id] = entry
	} else {
		// New entry
		c.events <- Event{entry, OpAdded}
		c.entries[id] = entry
	}
	c.refresh()
}

// Returns true if a query should be made right now. Remember to call `Queried()` after the
// query has been sent.
func (c *cache) ShouldQuery() bool {
	return c.nextPeriodic.Before(c.now) || c.nextLivecheck.Before(c.now)
}

// Should be called once a query has been made.
func (c *cache) Queried() {
	// RFC6762 Section 5.2: [...] the interval between the first two queries MUST be at least one
	// second, the intervals between successive queries MUST increase by at least a factor of two.
	interval := c.now.Sub(c.lastQuery) * 2
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
func (c *cache) NextTimeout() time.Duration {
	// TODO: Add jitter to avoid timing collisions with other queriers.
	soonest := c.nextPeriodic
	if c.nextExpiry.Before(soonest) {
		soonest = c.nextExpiry
	}
	if c.nextLivecheck.Before(soonest) {
		soonest = c.nextLivecheck
	}
	return soonest.Sub(c.now)
}

// Close the event channel
func (c *cache) Close() {
	close(c.events)
}

// Recalculates nextExpiry and nextLivecheck
func (c *cache) refresh() {
	// Use maxInterval simply for a large time value
	c.nextExpiry, c.nextLivecheck = c.now.Add(maxInterval), c.now.Add(maxInterval)
	for k, entry := range c.entries {

		// Compute inferred ttl
		ttl := entry.TTL
		if c.maxTTL != 0 && ttl > c.maxTTL {
			ttl = c.maxTTL
		}

		// If expired, remove instantly
		expiry := entry.seenAt.Add(time.Second * time.Duration(ttl))
		if expiry.Before(c.now) {
			c.events <- Event{entry, OpRemoved}
			delete(c.entries, k)
			continue
		}

		// Update next expiry
		if expiry.Before(c.nextExpiry) {
			c.nextExpiry = expiry
		}

		// An entry has already been queried if it hasn't been seen since the last query
		if entry.seenAt.Before(c.lastQuery) {
			continue
		}

		// Update next livecheck
		liveCheck := entry.seenAt.Add(time.Second * time.Duration(ttl) * 9 / 10)
		if liveCheck.Before(c.nextLivecheck) {
			c.nextLivecheck = liveCheck
		}
	}
}
