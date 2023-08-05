package zeroconf

import (
	"context"
	"fmt"
	"math/rand"
	"net"
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
	conn            *dualConn
	unannouncements bool
}

type clientOpts struct {
	listenOn        IPType
	ifaces          []net.Interface
	unannouncements bool
}

// ClientOption fills the option struct to configure intefaces, etc.
type ClientOption func(*clientOpts)

// SelectIPTraffic selects the type of IP packets (IPv4, IPv6, or both) this
// instance listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, may contain
// both DNS A and AAAA entries.
func SelectIPTraffic(t IPType) ClientOption {
	return func(o *clientOpts) {
		o.listenOn = t
	}
}

// SelectIfaces selects the interfaces to query for mDNS records
func SelectIfaces(ifaces []net.Interface) ClientOption {
	return func(o *clientOpts) {
		o.ifaces = ifaces
	}
}

// Emit an entry with an expiry in the past if a previously emitted entry is unannounced
// or if its TTL expires. With unannouncements, you won't see refreshed services, only presence
// changes. This gives you (a) earlier detection of disconnected clients and (b) you don't need to
// maintain any expiry timers yourself.
func Unannouncements() ClientOption {
	return func(o *clientOpts) {
		o.unannouncements = true
	}
}

// Browse for all services of a given type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Browse(ctx context.Context, service, domain string, entries chan<- *ServiceEntry, opts ...ClientOption) error {
	cl, err := newClient(applyOpts(opts...))
	if err != nil {
		return err
	}
	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	params.isBrowsing = true
	return cl.run(ctx, params)
}

// Lookup a specific service by its name and type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
func Lookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry, opts ...ClientOption) error {
	cl, err := newClient(applyOpts(opts...))
	if err != nil {
		return err
	}
	params := defaultParams(service)
	params.Instance = instance
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	return cl.run(ctx, params)
}

func applyOpts(options ...ClientOption) clientOpts {
	// Apply default configuration and load supplied options.
	var conf = clientOpts{
		listenOn: IPv4AndIPv6,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}
	return conf
}

func (c *client) run(ctx context.Context, params *lookupParams) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mainloop(ctx, params)
	}()

	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	err := c.periodicQuery(ctx, params)
	cancel()
	<-done
	return err
}

// defaultParams returns a default set of QueryParams.
func defaultParams(service string) *lookupParams {
	return newLookupParams("", service, "local", false, make(chan *ServiceEntry))
}

// Client structure constructor
func newClient(opts clientOpts) (*client, error) {
	conn, err := newDualConn(opts.ifaces, opts.listenOn)
	if err != nil {
		return nil, err
	}

	return &client{
		conn:            conn,
		unannouncements: opts.unannouncements,
	}, nil
}

var cleanupFreq = 10 * time.Second

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context, params *lookupParams) {
	// start listening for responses
	msgCh := make(chan MsgMeta, 32)

	go c.conn.RunReader(msgCh)

	// Iterate through channels from listeners goroutines
	sentEntries := make(map[string]*ServiceEntry)

	ticker := time.NewTicker(cleanupFreq)
	defer ticker.Stop()
	for {
		var entries map[string]*ServiceEntry
		var now time.Time
		select {
		case <-ctx.Done():
			// Context expired. Notify subscriber that we are done here.
			params.done()
			c.shutdown()
			return
		case t := <-ticker.C:
			for k, e := range sentEntries {
				if t.After(e.Expiry) {
					if c.unannouncements {
						params.Entries <- e
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
					if params.ServiceName() != rr.Hdr.Name {
						continue
					}
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Ptr {
						continue
					}
					if _, ok := entries[rr.Ptr]; !ok {
						entries[rr.Ptr] = newServiceEntry(
							trimDot(strings.Replace(rr.Ptr, rr.Hdr.Name, "", -1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Ptr].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				case *dns.SRV:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = newServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].HostName = rr.Target
					entries[rr.Hdr.Name].Port = int(rr.Port)
					entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				case *dns.TXT:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = newServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
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
					params.Entries <- e
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
			if params.ServiceRecord.ServiceTypeName() != params.ServiceRecord.ServiceName() {
				// Require at least one resolved IP address for ServiceEntry
				// TODO: wait some more time as chances are high both will arrive.
				if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
					continue
				}
			}
			// Submit entry to subscriber and cache it.
			// This is also a point to possibly stop probing actively for a
			// service entry.
			params.Entries <- e
			sentEntries[k] = e
			if !params.isBrowsing {
				params.disableProbing()
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
func (c *client) periodicQuery(ctx context.Context, params *lookupParams) error {
	// Do the first query immediately.
	if err := c.query(params); err != nil {
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
		case <-params.stopProbing:
			// Chan is closed (or happened in the past).
			// Done here. Received a matching mDNS entry.
			return nil
		case <-ctx.Done():
			if params.isBrowsing {
				return nil
			}
			return ctx.Err()
		}

		if err := c.query(params); err != nil {
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
func (c *client) query(params *lookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// send the query
	m := new(dns.Msg)
	if params.Instance != "" { // service instance name lookup
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
		m.Question = []dns.Question{
			{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
			{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		}
	} else if len(params.Subtypes) > 0 { // service subtype browse
		m.SetQuestion(params.Subtypes[0], dns.TypePTR)
	} else { // service name browse
		m.SetQuestion(serviceName, dns.TypePTR)
	}
	m.RecursionDesired = false
	return c.conn.WriteMulticastAll(m)
}
