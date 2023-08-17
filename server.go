package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// RFC6762 Section 8.3: The Multicast DNS responder MUST send at least two unsolicited
	// responses
	announceCount = 2
)

var defaultHostname, _ = os.Hostname()

// Publish a service entry. Instance and Port are required, while Text is optional.
// Addrs and Hostname are determined automatically, but can be overriden.
//
// Service type should be on the form `_my-service._tcp` or `_my-service._udp`
//
// You may add subtypes after a comma, e.g. `_my-service._tcp,_printer,_ipp`.
// By default, the domain `local` is used, but you can override it by adding
// path components, e.g. `_my-service._tcp.custom.dev` (not recommended).
func Publish(ctx context.Context, entry *ServiceEntry, serviceType string, conf *Config) error {
	if conf == nil {
		conf = new(Config)
	}

	service := parseService(serviceType)
	if err := service.Validate(); err != nil {
		return err
	}

	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return err
	}
	if entry.Hostname == "" {
		entry.Hostname = fmt.Sprintf("%v.%v", defaultHostname, service.Domain)
	}
	if err := entry.Validate(); err != nil {
		conn.Close()
		return err
	}

	s := &server{
		conn:    conn,
		service: service,
		entry:   entry,
	}
	err = s.serve(ctx)
	s.conn.Close()
	return err
}

// Server structure encapsulates both IPv4/IPv6 UDP connections
type server struct {
	service *ServiceRecord
	entry   *ServiceEntry
	conn    *dualConn
}

func (s *server) serve(ctx context.Context) error {
	s.conn.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancelCause(ctx)
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.recv(ctx)
	}()
	go func() {
		defer wg.Done()
		if err := s.announce(ctx); err != nil {
			cancel(err)
		}
	}()
	<-ctx.Done()
	now := time.Now()
	s.conn.SetDeadline(now)
	wg.Wait()

	s.conn.SetWriteDeadline(now.Add(10 * time.Millisecond))
	return errors.Join(context.Cause(ctx), s.unregister())
}

// recv4 is a long running routine to receive packets from an interface
func (s *server) recv(ctx context.Context) {
	msgCh := make(chan MsgMeta, 32)
	go s.conn.RunReader(msgCh)

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			_ = s.handleQuery(msg.Msg, msg.IfIndex, msg.From)
		}
	}
}

// Generate DNS records with the IPs (A/AAAA) for the provided interface (unless addrs were
// provided by the user).
func (s *server) recordsForIface(iface *Interface, unannounce bool) []dns.RR {
	// Copy the entry to create a new one with the right ips
	entry := *s.entry

	if len(s.entry.Addrs) == 0 {
		entry.Addrs = append(entry.Addrs, iface.v4...)
		entry.Addrs = append(entry.Addrs, iface.v6...)
	}

	return recordsFromService(s.service, &entry, unannounce)
}

// handleQuery is used to handle an incoming query
func (s *server) handleQuery(query *dns.Msg, ifIndex int, from net.Addr) (err error) {

	// RFC6762 Section 8.2: Probing messages are ignored, for now.
	if len(query.Ns) > 0 || len(query.Question) == 0 {
		return nil
	}
	iface := s.conn.ifaces[ifIndex]
	if iface == nil {
		return nil
	}

	// TODO: Cache these records in a iface idx -> records map
	records := s.recordsForIface(iface, false)

	// RFC6762 Section 5.2: Multiple questions in the same message are responded to individually.
	for _, q := range query.Question {

		// Check that
		resp := dns.Msg{}
		resp.SetReply(query)
		resp.Compress = true
		resp.RecursionDesired = false
		resp.Authoritative = true
		resp.Question = nil // RFC6762 Section 6: "responses MUST NOT contain any questions"

		resp.Answer = answerTo(records, query.Answer, q)
		if len(resp.Answer) == 0 {
			continue
		}
		resp.Extra = extraRecords(records, resp.Answer)

		if q.Qclass&qClassUnicastResponse != 0 {
			err = s.conn.WriteUnicast(&resp, ifIndex, from)
		} else {
			err = s.conn.WriteMulticast(&resp, ifIndex, from)
		}
	}

	return err
}

// Perform probing & announcement
func (s *server) announce(ctx context.Context) error {
	// TODO: implement a proper probing & conflict resolution

	// From RFC6762
	//    The Multicast DNS responder MUST send at least two unsolicited
	//    responses, one second apart. To provide increased robustness against
	//    packet loss, a responder MAY send up to eight unsolicited responses,
	//    provided that the interval between unsolicited responses increases by
	//    at least a factor of two with every response sent.

	timeout := time.Second
	for i := 0; i < announceCount; i++ {
		for _, iface := range s.conn.ifaces {

			resp := new(dns.Msg)
			resp.MsgHdr.Response = true
			resp.MsgHdr.Authoritative = true
			resp.Compress = true

			resp.Answer = s.recordsForIface(iface, false)
			if err := s.conn.WriteMulticast(resp, iface.Index, nil); err != nil {
				log.Printf("[ERR] zeroconf: failed to send announcement: %v\n", err)
			}
		}
		if err := sleepContext(ctx, timeout); err != nil {
			return err
		}
		timeout *= 2
	}
	return nil
}

func (s *server) unregister() error {

	for _, iface := range s.conn.ifaces {
		resp := new(dns.Msg)
		resp.MsgHdr.Response = true
		resp.Compress = true
		resp.Answer = s.recordsForIface(iface, true)
		if err := s.conn.WriteMulticast(resp, iface.Index, nil); err != nil {
			log.Printf("[ERR] zeroconf: failed to send unannouncement: %v\n", err)
		}
	}
	return nil
}
