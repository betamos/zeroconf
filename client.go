package zeroconf

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
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
)

// A client which publishes and/or browses for services.
type Client struct {
	wg     sync.WaitGroup
	conn   *conn
	opts   *Options
	reload chan struct{}
}

// Create a new zeroconf client.
func newClient(opts *Options) (*Client, error) {
	conn, err := newConn(opts.ifacesFn, opts.network)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, opts: opts, reload: make(chan struct{}, 1)}

	c.wg.Add(1)
	c.opts.logger.Debug("open socket", "ifaces", c.conn.ifaces)
	go c.serve()
	return c, nil
}

// The main loop serving a client
func (c *Client) serve() error {
	defer c.wg.Done()
	c.conn.SetReadDeadline(time.Time{})

	msgCh := make(chan msgMeta, 32)
	go c.conn.RunReader(msgCh)

	var (
		bo    = newBackoff(minInterval, maxInterval)
		timer = time.NewTimer(0)
	)
	defer timer.Stop()

loop:
	for {
		var (
			isPeriodic bool
			now        time.Time
			msg        *msgMeta
		)
		// Note the timer is always stopped after the `select`
		select {
		case <-c.reload:
			if !timer.Stop() {
				<-timer.C
			}
			now = time.Now()
			bo.reset()
			_, err := c.conn.loadIfaces()
			if err != nil {
				c.opts.logger.Warn("reload failed (ifaces unchanged)", "err", err)
			}
			c.opts.logger.Debug("reload", "ifaces", c.conn.ifaces)
		case m, ok := <-msgCh:
			if !timer.Stop() {
				<-timer.C
			}
			now = time.Now()
			if !ok {
				break loop
			}
			msg = &m
		case now = <-timer.C:
		}
		// Use wall time exclusively in order to restore accurate state when waking from sleep,
		// (time jumps forward) such as cache expiry. However, the user still needs to monitor time
		// and reload in order to reset the periodic announcements and queries.
		now = now.Round(0)

		isPeriodic = bo.advance(now)

		// Publish initial announcements
		if c.opts.publisher != nil && isPeriodic && bo.n <= announceCount {
			err := c.broadcastRecords(false)
			c.opts.logger.Debug("announce", "err", err)
		}

		// Handle any queries
		if c.opts.publisher != nil && msg != nil {
			_ = c.handleQuery(*msg)
		}

		// Handle all browser-related maintenance
		next := bo.next
		if c.opts.browser != nil {
			nextBrowserDeadline := c.advanceBrowser(now, msg, isPeriodic)
			next = earliest(next, nextBrowserDeadline)
		}

		timer.Reset(next.Sub(now))
	}
	return nil
}

// Reloads network interfaces and resets backoff timers, in order to reach
// newly available peers. This has no effect if the client is closed.
func (c *Client) Reload() {
	select {
	case c.reload <- struct{}{}:
	default:
	}
}

// Unannounces any published services and then closes the network conn. No more events are produced
// afterwards.
func (c *Client) Close() error {
	c.conn.SetReadDeadline(time.Now())
	c.wg.Wait()
	if c.opts.publisher != nil {
		err := c.broadcastRecords(true)
		c.opts.logger.Debug("unannounce", "err", err)
	}
	return c.conn.Close()
}

// Generate DNS records with the IPs (A/AAAA) for the provided interface (unless addrs were
// provided by the user).
func (c *Client) recordsForIface(iface *connInterface, unannounce bool) []dns.RR {
	// Copy the service to create a new one with the right ips
	svc := *c.opts.publisher.svc

	if len(svc.Addrs) == 0 {
		svc.Addrs = append(svc.Addrs, iface.v4...)
		svc.Addrs = append(svc.Addrs, iface.v6...)
	}

	return recordsFromService(c.opts.publisher.ty, &svc, unannounce)
}

func (c *Client) handleQuery(msg msgMeta) error {
	if c.opts.publisher.svc == nil {
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
func (c *Client) handleQueryForIface(query *dns.Msg, iface *connInterface, src netip.Addr) (err error) {

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
	if c.opts.publisher == nil {
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

func (c *Client) advanceBrowser(now time.Time, msg *msgMeta, isPeriodic bool) (next time.Time) {
	c.opts.browser.Advance(now)
	var svcs []*Service
	if msg != nil {
		svcs = servicesFromRecords(msg.Msg, c.opts.browser.ty)
	}
	for _, svc := range svcs {
		if c.opts.publisher != nil && svc.Name == c.opts.publisher.svc.Name {
			continue
		}
		svc.ttl = min(svc.ttl, c.opts.maxAge)

		// TODO: Debug log when services are refreshed?
		c.opts.browser.Put(svc)
	}
	if c.opts.browser.ShouldQuery() || isPeriodic {
		err := c.broadcastQuery()
		c.opts.logger.Debug("query", "err", err)
		c.opts.browser.Queried()
	}
	return c.opts.browser.NextDeadline()
}

// Performs the actual query by service name.
func (c *Client) broadcastQuery() error {
	m := new(dns.Msg)
	m.Question = append(m.Question, dns.Question{
		Name:   queryName(c.opts.browser.ty),
		Qtype:  dns.TypePTR,
		Qclass: dns.ClassINET,
	})
	if pub := c.opts.publisher; pub != nil {
		// Include self-published service as "known answers", to avoid responding to ourselves
		m.Answer = ptrRecords(pub.ty, pub.svc, false)
	}
	m.Id = dns.Id()
	m.Compress = true
	m.RecursionDesired = false

	var errs []error
	for _, iface := range c.conn.ifaces {
		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		err := c.conn.WriteMulticast(m, iface.Index, nil)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}
