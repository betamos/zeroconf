package zeroconf

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

// IPType specifies the IP traffic the client listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, often contain
// both DNS A and AAAA entries.
type IPType uint8

// Options for IPType.
const (
	IPv4        IPType = 0x01
	IPv6        IPType = 0x02
	IPv4AndIPv6        = IPv4 | IPv6 // default option
)

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	conn *dualConn

	service *ServiceRecord
	cache   *cache
}

// Browse for all services of a given type, e.g. `_my-service._udp` or `_http._tcp`.
// To browse only for specific subtypes, append it after a comma, e.g. `_my-service._tcp,_printer`.
// Events are sent to the provided callback.
// It blocks until the context is canceled (or an error occurs).
func Browse(ctx context.Context, serviceStr string, cb func(Event), conf *Config) error {
	// TODO: Possibly construct a query instead of creating this record.
	if conf == nil {
		conf = new(Config)
	}
	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return err
	}
	service := parseService(serviceStr)
	if len(service.Subtypes) > 1 {
		return errors.New("browsing supports only a single subtype")
	}
	if err = service.Validate(); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	cl := &client{
		conn:    conn,
		cache:   newCache(cb, conf.maxAge()),
		service: service,
	}
	return cl.run(ctx)
}

// Lookup a specific instance of a service.
func Lookup(ctx context.Context, instance, service string, conf *Config) (entry *ServiceEntry, err error) {
	ctx, cancel := context.WithCancel(ctx)
	err = Browse(ctx, service, func(event Event) {
		if event.Op == OpAdded && instance == event.Instance {
			entry = event.ServiceEntry
			cancel()
		}
	}, conf)
	cancel()
	return
}

func (c *client) run(ctx context.Context) error {
	// RFC6762 Section 8.3: [...] a Multicast DNS querier SHOULD also delay the first query of
	// the series by a randomly chosen amount in the range 20-120 ms.
	if err := sleepContext(ctx, time.Duration(20+rand.Int63n(100))*time.Millisecond); err != nil {
		return err
	}

	err := c.mainloop(ctx)

	err = errors.Join(err, c.conn.Close())
	return err
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context) error {
	// start listening for responses
	msgCh := make(chan MsgMeta, 32)
	go c.conn.RunReader(msgCh)

	timer := time.NewTimer(0)
	defer timer.Stop()
	var now time.Time
	for {
		var entries []*ServiceEntry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now = <-timer.C:
		case msg, ok := <-msgCh:
			if !ok {
				return nil
			}

			if entries = serviceFromRecords(msg.Msg, c.service); entries == nil {
				continue
			}

			// Prepare to operate on the cache below
			now = time.Now()
			if !timer.Stop() {
				<-timer.C
			}
		}

		c.cache.Advance(now)

		for _, entry := range entries {
			c.cache.Put(entry)
		}
		clear(entries)

		if c.cache.ShouldQuery() {
			_ = c.query() // TODO: Log?
			c.cache.Queried()
		}

		// Invariant: the timer is currently stopped, so can be safely reset
		timer.Reset(c.cache.NextDeadline().Sub(now))
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
// start response listeners goroutines and loops over the entries channel.
func (c *client) query() error {
	m := new(dns.Msg)
	m.Question = append(m.Question, dns.Question{
		Name:   c.service.queryName(),
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	})
	m.Id = dns.Id()
	m.Compress = true
	m.RecursionDesired = false
	return c.conn.WriteMulticastAll(m)
}
