package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
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

var initialQueryInterval = 4 * time.Second

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	conn  *dualConn
	cache map[string]*ServiceEntry

	service *ServiceRecord
	entries chan<- *ServiceEntry // Entries Channel

	isBrowsing      bool
	cacheTimer      *time.Timer
	unannouncements bool
}

// Browse for all services of a given type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Browse(ctx context.Context, service string, entries chan<- *ServiceEntry, conf *Config) error {
	if conf == nil {
		conf = new(Config)
	}
	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return err
	}
	cl := &client{
		conn:            conn,
		cache:           make(map[string]*ServiceEntry),
		entries:         entries,
		service:         newServiceRecord("", service, conf.domain()),
		cacheTimer:      time.NewTimer(aLongTime),
		unannouncements: true,
		isBrowsing:      true,
	}
	return cl.run(ctx)
}

// Lookup a specific service by its name and type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Lookup(ctx context.Context, instance, service string, entries chan<- *ServiceEntry, conf *Config) error {
	if conf == nil {
		conf = new(Config)
	}
	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return err
	}
	cl := &client{
		conn:            conn,
		cache:           make(map[string]*ServiceEntry),
		entries:         entries,
		service:         newServiceRecord(instance, service, conf.domain()),
		cacheTimer:      time.NewTimer(aLongTime),
		unannouncements: true,
		isBrowsing:      false,
	}
	return cl.run(ctx)
}

func (c *client) run(ctx context.Context) error {
	if c.isBrowsing {
		// RFC6762 Section 8.3: [...] a Multicast DNS querier SHOULD also delay the first query of
		// the series by a randomly chosen amount in the range 20-120 ms.
		if err := sleepContext(ctx, time.Duration(20+rand.Int63n(100))*time.Millisecond); err != nil {
			return err
		}
	}

	err := c.mainloop(ctx)
	err = errors.Join(err, c.shutdown())
	return err
}

var cleanupFreq = 10 * time.Second

func (c *client) clearCache(now time.Time) {
	next := now.Add(aLongTime)
	for k, e := range c.cache {
		if now.After(e.Expiry) {
			if c.unannouncements {
				c.entries <- e
			}
			delete(c.cache, k)
		} else if e.Expiry.Before(next) {
			next = e.Expiry
		}
	}
	if c.cacheTimer.Stop() {
		c.cacheTimer.Reset(next.Sub(now))
	}
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context) error {
	// start listening for responses
	msgCh := make(chan MsgMeta, 32)
	go c.conn.RunReader(msgCh)

	const maxInterval = 60 * time.Second
	interval := initialQueryInterval
	queryTimer := time.NewTimer(0)
	defer queryTimer.Stop()

	defer c.cacheTimer.Stop() // TODO: Clear better
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-queryTimer.C:
			queryTimer.Reset(interval)
			_ = c.query() // TODO: Log?

			// Exponential increase of the interval with jitter:
			// the new interval will be between 1.5x and 2.5x the old interval, capped at maxInterval.
			if interval != maxInterval {
				interval += time.Duration(rand.Int63n(interval.Nanoseconds())) + interval/2
				if interval > maxInterval {
					interval = maxInterval
				}
			}
			continue
		case now := <-c.cacheTimer.C:
			c.clearCache(now)
		case msg, ok := <-msgCh:
			if !ok {
				return nil
			}
			now := time.Now()
			c.processMsg(msg, now)
			c.clearCache(now)
		}
	}
}

func (c *client) processMsg(msg MsgMeta, now time.Time) {
	entries := make(map[string]*ServiceEntry)
	sections := append(msg.Answer, msg.Ns...)
	sections = append(sections, msg.Extra...)

	s := c.service // shorthand

	for _, answer := range sections {
		switch rr := answer.(type) {
		case *dns.PTR:
			if s.ServiceName() != rr.Hdr.Name {
				continue
			}
			if s.ServiceInstanceName() != "" && s.ServiceInstanceName() != rr.Ptr {
				continue
			}
			if _, ok := entries[rr.Ptr]; !ok {
				entries[rr.Ptr] = newServiceEntry(
					trimDot(strings.Replace(rr.Ptr, rr.Hdr.Name, "", -1)),
					s.Service,
					s.Domain)
			}
			entries[rr.Ptr].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
		case *dns.SRV:
			if s.ServiceInstanceName() != "" && s.ServiceInstanceName() != rr.Hdr.Name {
				continue
			} else if !strings.HasSuffix(rr.Hdr.Name, s.ServiceName()) {
				continue
			}
			if _, ok := entries[rr.Hdr.Name]; !ok {
				entries[rr.Hdr.Name] = newServiceEntry(
					trimDot(strings.Replace(rr.Hdr.Name, s.ServiceName(), "", 1)),
					s.Service,
					s.Domain)
			}
			entries[rr.Hdr.Name].HostName = rr.Target
			entries[rr.Hdr.Name].Port = int(rr.Port)
			entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
		case *dns.TXT:
			if s.ServiceInstanceName() != "" && s.ServiceInstanceName() != rr.Hdr.Name {
				continue
			} else if !strings.HasSuffix(rr.Hdr.Name, s.ServiceName()) {
				continue
			}
			if _, ok := entries[rr.Hdr.Name]; !ok {
				entries[rr.Hdr.Name] = newServiceEntry(
					trimDot(strings.Replace(rr.Hdr.Name, s.ServiceName(), "", 1)),
					s.Service,
					s.Domain)
			}
			entries[rr.Hdr.Name].Text = rr.Txt
			entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
		}
	}
	// Associate IPs in a second round as other fields should be filled by now.
	for _, answer := range sections {
		switch rr := answer.(type) {
		case *dns.A:
			for k, e := range entries {
				if e.HostName == rr.Hdr.Name {
					entries[k].AddrIPv4 = append(entries[k].AddrIPv4, rr.A)
				}
			}
		case *dns.AAAA:
			for k, e := range entries {
				if e.HostName == rr.Hdr.Name {
					entries[k].AddrIPv6 = append(entries[k].AddrIPv6, rr.AAAA)
				}
			}
		}
	}

	for k, e := range entries {
		if !e.Expiry.After(now) {
			// Implies TTL=0, meaning a "Goodbye Packet".
			if _, ok := c.cache[k]; ok && c.unannouncements {
				c.entries <- e
			}
			delete(c.cache, k)
			continue
		}
		if _, ok := c.cache[k]; ok {
			if c.unannouncements {
				c.cache[k] = e
			}
			// Already sent, suppress duplicates
			continue
		}

		// If this is an DNS-SD query do not throw PTR away.
		// It is expected to have only PTR for enumeration
		if s.ServiceTypeName() != s.ServiceName() {
			// Require at least one resolved IP address for ServiceEntry
			// TODO: wait some more time as chances are high both will arrive.
			if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
				continue
			}
		}
		// Submit entry to subscriber and cache it.
		// This is also a point to possibly stop probing actively for a
		// service entry.
		c.entries <- e
		c.cache[k] = e
	}
}

// Shutdown client will close currently open connections and channel implicitly.
func (c *client) shutdown() error {
	err := c.conn.Close()
	close(c.entries) // TODO: Make thread safe?
	c.cacheTimer.Stop()
	for range c.cacheTimer.C {
	}
	return err
}

// Performs the actual query by service name (browse) or service instance name (lookup),
// start response listeners goroutines and loops over the entries channel.
func (c *client) query() error {
	var serviceName, serviceInstanceName string
	s := c.service // shorthand
	serviceName = fmt.Sprintf("%s.%s.", trimDot(s.Service), trimDot(s.Domain))

	// send the query
	m := new(dns.Msg)
	if s.Instance != "" { // service instance name lookup
		serviceInstanceName = fmt.Sprintf("%s.%s", s.Instance, serviceName)
		m.Question = []dns.Question{
			{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
			{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		}
	} else if len(s.Subtypes) > 0 { // service subtype browse
		m.SetQuestion(s.Subtypes[0], dns.TypePTR)
	} else { // service name browse
		m.SetQuestion(serviceName, dns.TypePTR)
	}
	m.RecursionDesired = false
	return c.conn.WriteMulticastAll(m)
}
