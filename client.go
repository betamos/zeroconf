package zeroconf

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	conn *dualConn

	service *Service
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
	conn, err := newDualConn(conf.interfaces(), conf.ipType())
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
func Lookup(ctx context.Context, instanceName, service string, conf *Config) (instance *Instance, err error) {
	ctx, cancel := context.WithCancel(ctx)
	err = Browse(ctx, service, func(event Event) {
		if event.Op == OpAdded && instanceName == event.Name {
			instance = event.Instance
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
	var (
		timer = time.NewTimer(0)
		now   time.Time
		msgCh = make(chan MsgMeta, 32)
		is    []*Instance
	)

	go c.conn.RunReader(msgCh)
	defer timer.Stop()

	done := ctx.Done()
loop:
	for {
		select {
		case <-done:
			c.conn.SetReadDeadline(time.Now())
			done = nil // never canceled
		case now = <-timer.C:
		case msg, ok := <-msgCh:
			if !ok {
				break loop
			}
			if is = serviceFromRecords(msg.Msg, c.service); len(is) == 0 {
				continue
			}
			// Prepare to operate on the cache below
			now = time.Now()
			if !timer.Stop() {
				<-timer.C
			}
		}

		c.cache.Advance(now)

		for _, i := range is {
			// TODO: Debug log when no events are emitted
			c.cache.Put(i)
		}
		is = nil

		if c.cache.ShouldQuery() {
			_ = c.query() // TODO: Log?
			c.cache.Queried()
		}

		// Invariant: the timer is currently stopped, so can be safely reset
		timer.Reset(c.cache.NextDeadline().Sub(now))
	}
	return context.Cause(ctx)
}

// Performs the actual query by service name.
func (c *client) query() error {
	c.conn.loadIfaces()
	m := new(dns.Msg)
	m.Question = append(m.Question, dns.Question{
		Name:   c.service.queryName(),
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	})
	m.Id = dns.Id()
	m.Compress = true
	m.RecursionDesired = false

	var errs []error
	for _, iface := range c.conn.ifaces {
		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := c.conn.WriteMulticast(m, iface.Index, nil)
		slog.Debug("query", "iface", iface.Name, "err", err)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}
