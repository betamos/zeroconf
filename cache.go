package zeroconf

import (
	"fmt"
	"math/rand"
	"time"
)

const (
	minInterval = 4 * time.Second
	maxInterval = time.Hour

	// TODO: Max time window to coalesce changes that occur simultaneously
	// maxCoalesceDuration = time.Millisecond * 25
)

// An operation on the state of the cache.
type Op int

func (op Op) String() string {
	switch op {
	case OpAdded:
		return "[+]"
	case OpRemoved:
		return "[-]"
	default:
		return "[?]"
	}
}

const (
	// A service was discovered.
	OpAdded Op = iota

	// A service expired or was intentionally removed.
	OpRemoved
)

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
	instances map[string]*Instance
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
		instances: make(map[string]*Instance),
		cb:        cb,
		maxAge:    maxAge,
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

func (c *cache) Put(instance *Instance) {
	k := instance.Name
	instance.seenAt = c.now
	if instance.ttl == 0 {
		// Existing instance removed through a "Goodbye Packet"
		if _, ok := c.instances[k]; ok {
			c.cb(Event{instance, OpRemoved})
		}
		delete(c.instances, k)
	} else if _, ok := c.instances[k]; ok {
		// Existing instance extended, suppress duplicates
		// TODO: Compare and send updates.
		c.instances[k] = instance
	} else {
		// New instance
		c.cb(Event{instance, OpAdded})
		c.instances[k] = instance
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
	for k, instance := range c.instances {

		// Compute inferred ttl
		ttl := min(c.maxAge, time.Second*time.Duration(instance.ttl))

		// If expired, remove instantly
		expiry := instance.seenAt.Add(ttl)
		if expiry.Before(c.now) {
			c.cb(Event{instance, OpRemoved})
			delete(c.instances, k)
			continue
		}

		// Update next expiry
		if expiry.Before(c.nextExpiry) {
			c.nextExpiry = expiry
		}

		// An instance has already been queried if it hasn't been seen since the last query
		if instance.seenAt.Before(c.lastQuery) {
			continue
		}

		// Update next livecheck
		floatDur := float64(ttl) * (0.80 + c.entropy*0.17) // 80-97% of ttl
		liveCheck := instance.seenAt.Add(time.Duration(floatDur))
		if liveCheck.Before(c.nextLivecheck) {
			c.nextLivecheck = liveCheck
		}
	}
}
