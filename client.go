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

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	conn *dualConn

	service *ServiceRecord
	cache   *cache

	isBrowsing bool
}

// Browse for all services of a given type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Browse(ctx context.Context, service string, entries chan<- Event, conf *Config) error {
	if conf == nil {
		conf = new(Config)
	}
	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return err
	}
	cl := &client{
		conn:       conn,
		cache:      newCache(entries, 0),
		service:    newServiceRecord("", service, conf.domain()),
		isBrowsing: true,
	}
	return cl.run(ctx)
}

// Lookup a specific service by its name and type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Lookup(ctx context.Context, instance, service string, entries chan<- Event, conf *Config) error {
	if conf == nil {
		conf = new(Config)
	}
	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return err
	}
	cl := &client{
		conn:       conn,
		cache:      newCache(entries, 120),
		service:    newServiceRecord("", service, conf.domain()),
		isBrowsing: false,
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

	c.cache.Close()
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
		var newEntries map[string]*ServiceEntry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now = <-timer.C:
		case msg, ok := <-msgCh:
			if !ok {
				return nil
			}
			newEntries = c.processMsg(msg)
			if len(newEntries) == 0 {
				continue // as if nothing happened
			}

			// Prepare to operate on the cache below
			now = time.Now()
			if !timer.Stop() {
				<-timer.C
			}
		}

		c.cache.Advance(now)

		// Add new entries to the cache, if any
		for k, e := range newEntries {
			// If this is an DNS-SD query do not throw PTR away.
			// It is expected to have only PTR for enumeration
			if c.service.ServiceTypeName() != c.service.ServiceName() {
				// Require at least one resolved IP address for ServiceEntry
				// TODO: wait some more time as chances are high both will arrive.
				if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
					continue
				}
			}
			c.cache.Put(k, e)
		}

		if c.cache.ShouldQuery() {
			_ = c.query() // TODO: Log?
			c.cache.Queried()
		}

		// Invariant: the timer is currently stopped, so can be safely reset
		timer.Reset(c.cache.NextTimeout())
	}
}

func (c *client) processMsg(msg MsgMeta) map[string]*ServiceEntry {
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
			entries[rr.Ptr].TTL = rr.Hdr.Ttl
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
			entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
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
			entries[rr.Hdr.Name].TTL = rr.Hdr.Ttl
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
	return entries
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
