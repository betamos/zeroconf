package zeroconf

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/miekg/dns"
)

const (
	// RFC6762 Section 8.3: The Multicast DNS responder MUST send at least two unsolicited
	// responses
	announceCount = 4

	// These intervals are for exponential backoff, used for periodic actions like sending queries
	minInterval = 2 * time.Second
	maxInterval = time.Hour

	// Enough to send a UDP packet without causing a timeout error
	writeTimeout = 10 * time.Millisecond

	// Max time window to coalesce cache-updates
	cacheDelay = time.Millisecond * 50
)

// A zeroconf client which publishes and/or browses for services.
//
// The methods return a self-pointer for optional method chaining.
type Client struct {
	done   chan struct{}
	conn   *conn
	opts   *options
	reload chan struct{}
}

// Returns a new client. Next, provide your options and then call `Open`.
func New() *Client {
	return &Client{
		opts:   defaultOpts(),
		reload: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

// Opens the socket and starts the zeroconf service. All options must be set beforehand,
// including at least `Browse`, `Publish`, or both.
func (c *Client) Open() (_ *Client, err error) {
	if err = c.opts.validate(); err != nil {
		return nil, err
	}
	c.conn, err = newConn(c.opts.ifacesFn, c.opts.network)
	if err != nil {
		return nil, err
	}
	c.opts.logger.Debug("open socket", "ifaces", c.conn.ifaces)
	msgCh := make(chan msgMeta, 32)
	go c.conn.RunReader(msgCh)
	go c.serve(msgCh)
	return c, nil
}

// The main loop serving a client
func (c *Client) serve(msgCh <-chan msgMeta) {
	defer close(c.done)

	var (
		bo    = newBackoff(minInterval, maxInterval)
		timer = time.NewTimer(0)
	)
	defer timer.Stop()

loop:
	for {
		var (
			isPeriodic bool

			// Use wall time exclusively in order to restore accurate state when waking from sleep,
			// (time jumps forward) such as cache expiry.
			now time.Time
		)
		select {
		case <-c.reload:
			if !timer.Stop() {
				<-timer.C
			}
			now = time.Now().Round(0)
			bo.reset()
			_, err := c.conn.loadIfaces()
			if err != nil {
				c.opts.logger.Warn("reload failed (ifaces unchanged)", "err", err)
			}
			c.opts.logger.Debug("reload", "ifaces", c.conn.ifaces)
		case msg, ok := <-msgCh:
			now = time.Now().Round(0)
			if !ok {
				break loop
			}

			_ = c.handleQuery(msg)
			if c.handleResponse(now, msg) && timer.Stop() {
				// If the cache was touched, we want the update soon
				timer.Reset(cacheDelay)
			}
			continue
		case now = <-timer.C:
			now = now.Round(0)
		}
		// Invariant: the timer is stopped.

		isPeriodic = bo.advance(now)

		// Publish initial announcements
		if c.opts.publish != nil && isPeriodic && bo.n <= announceCount {
			err := c.broadcastRecords(false)
			c.opts.logger.Debug("announce", "err", err)
		}

		// Handle all browser-related maintenance
		nextBrowserDeadline := c.advanceBrowser(now, isPeriodic)
		nextTimeout := earliest(bo.next, nextBrowserDeadline).Sub(now)

		// Damage control: ensure timeout isn't firing all the time in case of a bug
		timer.Reset(max(200*time.Millisecond, nextTimeout))
	}
}

// Reloads network interfaces and resets backoff timers, in order to reach
// newly available peers. This has no effect if the client is closed.
func (c *Client) Reload() {
	select {
	case c.reload <- struct{}{}:
	default:
	}
}

// Gracefully stops all background tasks, unannounces any services and closes the socket.
func (c *Client) Close() error {
	c.conn.SetReadDeadline(time.Now())
	<-c.done
	if c.opts.publish != nil {
		err := c.broadcastRecords(true)
		c.opts.logger.Debug("unannounce", "err", err)
	}
	return c.conn.Close()
}

// Generate DNS records with the IPs (A/AAAA) for the provided interface (unless addrs were
// provided by the user).
func (c *Client) recordsForIface(iface *connInterface, unannounce bool) []dns.RR {
	// Copy the service to create a new one with the right ips
	svc := *c.opts.publish

	if len(svc.Addrs) == 0 {
		svc.Addrs = append(svc.Addrs, iface.v4...)
		svc.Addrs = append(svc.Addrs, iface.v6...)
	}

	return recordsFromService(&svc, unannounce)
}

func (c *Client) handleQuery(msg msgMeta) error {
	if c.opts.publish == nil {
		return nil
	}
	// RFC6762 Section 8.2: Probing messages are ignored, for now.
	if len(msg.Ns) > 0 || len(msg.Question) == 0 {
		return nil
	}

	// If we can't determine an interface source, we simply reply as if it were sent on all interfaces.
	var errs []error
	for _, iface := range c.conn.ifaces {
		if msg.IfIndex == 0 || msg.IfIndex == iface.Index {
			if err := c.handleQueryForIface(msg.Msg, iface, msg.Src); err != nil {
				errs = append(errs, fmt.Errorf("%v %w", iface.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// handleQuery is used to handle an incoming query
func (c *Client) handleQueryForIface(query *dns.Msg, iface *connInterface, src netip.AddrPort) (err error) {

	// TODO: Match quickly against the query without producing full records for each iface.
	records := c.recordsForIface(iface, false)

	// RFC6762 Section 5.2: Multiple questions in the same message are responded to individually.
	for _, q := range query.Question {

		// Check that
		resp := dns.Msg{}
		resp.SetReply(query)
		resp.Compress = true
		resp.RecursionDesired = false
		resp.Authoritative = true
		resp.Question = nil // RFC6762 Section 6: "responses MUST NOT contain any questions"

		resp.Answer, resp.Extra = answerTo(records, query.Answer, q)
		if len(resp.Answer) == 0 {
			continue
		}

		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		isUnicast := q.Qclass&qClassUnicastResponse != 0
		if isUnicast {
			err = c.conn.WriteUnicast(&resp, iface.Index, src)
		} else {
			err = c.conn.WriteMulticast(&resp, iface.Index, &src)
		}
		c.opts.logger.Debug("respond", "iface", iface.Name, "src", src, "unicast", isUnicast, "err", err)
	}

	return err
}

// Broadcast all records to all interfaces. If unannounce is set, the TTLs are zero
func (c *Client) broadcastRecords(unannounce bool) error {
	if c.opts.publish == nil {
		return nil
	}
	var errs []error
	for _, iface := range c.conn.ifaces {
		resp := new(dns.Msg)
		resp.MsgHdr.Response = true
		resp.MsgHdr.Authoritative = true
		resp.Compress = true
		resp.Answer = c.recordsForIface(iface, unannounce)

		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := c.conn.WriteMulticast(resp, iface.Index, nil)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Returns true if the browser needs to be advanced soon
func (c *Client) handleResponse(now time.Time, msg msgMeta) (changed bool) {
	if c.opts.browser == nil {
		return false
	}
	svcs := servicesFromRecords(msg.Msg)
	for _, svc := range svcs {
		// Exclude self-published services
		if c.opts.publish != nil && svc.Equal(c.opts.publish) {
			continue
		}

		// Ensure the service matches any of our "search types"
		if slices.IndexFunc(c.opts.browser.types, svc.Matches) == -1 {
			continue
		}
		changed = true
		// Set custom TTL unless this is an announcement (we treat TTL=1 as intent to unannounce)
		if c.opts.expiry > 0 && svc.ttl > time.Second {
			svc.ttl = c.opts.expiry
		}
		// Override self-reported addrs with source address instead, if enabled
		if c.opts.srcAddrs {
			svc.Addrs = []netip.Addr{msg.Src.Addr()}
		}
		// TODO: Debug log when services are refreshed?
		c.opts.browser.Put(svc, now)
	}
	return
}

func (c *Client) advanceBrowser(now time.Time, isPeriodic bool) time.Time {
	if c.opts.browser == nil {
		return now.Add(aLongTime)
	}
	if c.opts.browser.Advance(now) || isPeriodic {
		err := c.broadcastQuery()
		c.opts.logger.Debug("query", "err", err)
		c.opts.browser.Queried()
	}
	return c.opts.browser.NextDeadline()
}

// Performs the actual query by service name.
func (c *Client) broadcastQuery() error {
	m := new(dns.Msg)
	// Query for all browser types
	for _, ty := range c.opts.browser.types {
		m.Question = append(m.Question, dns.Question{
			Name:   queryName(ty),
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		})
	}
	if c.opts.publish != nil {
		// Include self-published service as "known answers", to avoid responding to ourselves
		m.Answer = ptrRecords(c.opts.publish, false)
	}
	m.Id = dns.Id()
	m.Compress = true
	m.RecursionDesired = false

	var errs []error
	for _, iface := range c.conn.ifaces {
		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := c.conn.WriteMulticast(m, iface.Index, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("idx %v: %w", iface.Index, err))
		}
	}

	return errors.Join(errs...)
}
