package zeroconf

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
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
	conn *dualConn

	service *ServiceRecord
	entries chan<- *ServiceEntry // Entries Channel

	isBrowsing      bool
	stopProbing     chan struct{}
	once            sync.Once
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
		entries:         entries,
		service:         newServiceRecord("", service, conf.domain()),
		conn:            conn,
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
		entries:         entries,
		service:         newServiceRecord(instance, service, conf.domain()),
		conn:            conn,
		unannouncements: true,
		isBrowsing:      false,
		stopProbing:     make(chan struct{}),
	}
	return cl.run(ctx)
}

func (c *client) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mainloop(ctx)
	}()

	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	err := c.periodicQuery(ctx)
	cancel()
	<-done
	return err
}

func (c *client) disableProbing() {
	c.once.Do(func() { close(c.stopProbing) })
}

var cleanupFreq = 10 * time.Second

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context) {
	// start listening for responses
	msgCh := make(chan MsgMeta, 32)

	go c.conn.RunReader(msgCh)

	// Iterate through channels from listeners goroutines
	sentEntries := make(map[string]*ServiceEntry)

	ticker := time.NewTicker(cleanupFreq)

	s := c.service // shorthand
	defer ticker.Stop()
	for {
		var entries map[string]*ServiceEntry
		var now time.Time
		select {
		case <-ctx.Done():
			// Context expired. Notify subscriber that we are done here.
			close(c.entries)
			c.shutdown()
			return
		case t := <-ticker.C:
			for k, e := range sentEntries {
				if t.After(e.Expiry) {
					if c.unannouncements {
						c.entries <- e
					}
					delete(sentEntries, k)
				}
			}
			continue
		case msg := <-msgCh:
			now = time.Now()
			entries = make(map[string]*ServiceEntry)
			sections := append(msg.Answer, msg.Ns...)
			sections = append(sections, msg.Extra...)

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
		}

		for k, e := range entries {
			if !e.Expiry.After(now) {
				// Implies TTL=0, meaning a "Goodbye Packet".
				if _, ok := sentEntries[k]; ok && c.unannouncements {
					c.entries <- e
				}
				delete(sentEntries, k)
				continue
			}
			if _, ok := sentEntries[k]; ok {
				if c.unannouncements {
					sentEntries[k] = e
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
			sentEntries[k] = e
			if !c.isBrowsing {
				c.disableProbing()
			}
		}
	}
}

// Shutdown client will close currently open connections and channel implicitly.
func (c *client) shutdown() {
	c.conn.Close()
}

// periodicQuery sens multiple probes until a valid response is received by
// the main processing loop or some timeout/cancel fires.
// TODO: move error reporting to shutdown function as periodicQuery is called from
// go routine context.
func (c *client) periodicQuery(ctx context.Context) error {
	if c.isBrowsing {
		// RFC6762 Section 8.3: [...] a Multicast DNS querier SHOULD also delay the first query of
		// the series by a randomly chosen amount in the range 20-120 ms.
		if err := sleepContext(ctx, time.Duration(20+rand.Int63n(100))*time.Millisecond); err != nil {
			return err
		}
	}
	if err := c.query(); err != nil {
		return err
	}

	const maxInterval = 60 * time.Second
	interval := initialQueryInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			// Wait for next iteration.
		case <-c.stopProbing:
			// Chan is closed (or happened in the past).
			// Done here. Received a matching mDNS entry.
			return nil
		case <-ctx.Done():
			if c.isBrowsing {
				return nil
			}
			return ctx.Err()
		}

		if err := c.query(); err != nil {
			return err
		}
		// Exponential increase of the interval with jitter:
		// the new interval will be between 1.5x and 2.5x the old interval, capped at maxInterval.
		if interval != maxInterval {
			interval += time.Duration(rand.Int63n(interval.Nanoseconds())) + interval/2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
		timer.Reset(interval)
	}
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
