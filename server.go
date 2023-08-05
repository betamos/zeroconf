package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// Number of Multicast responses sent for a query message (default: 1 < x < 9)
	multicastRepetitions = 2
)

// RFC6762 Section 10 says A/AAAA/PTR/SRV records SHOULD use TTL of 120 s, to account for
// network interface and IP address changes. For simplicity, all records use the same TTL.
var defaultTTL uint32 = 120

type serverOpts struct {
	ttl uint32
}

func applyServerOpts(options ...ServerOption) serverOpts {
	// Apply default configuration and load supplied options.
	var conf = serverOpts{
		ttl: defaultTTL,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}
	return conf
}

// ServerOption fills the option struct.
type ServerOption func(*serverOpts)

// TTL sets the TTL for DNS replies.
func TTL(ttl uint32) ServerOption {
	return func(o *serverOpts) {
		o.ttl = ttl
	}
}

// Register a service by given arguments. This call will take the system's hostname
// and lookup IP by that hostname.
func Register(instance, service, domain string, port int, text []string, ifaces []net.Interface, opts ...ServerOption) (*Server, error) {
	entry := newServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.Domain == "" {
		entry.Domain = "local."
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	var err error
	entry.HostName, err = os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("could not determine host")
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	conn, err := newDualConn(ifaces, IPv4AndIPv6)
	if err != nil {
		return nil, err
	}

	entry.AddrIPv4, entry.AddrIPv6 = conn.Addrs()

	// if entry.AddrIPv4 == nil && entry.AddrIPv6 == nil {
	// 	return nil, fmt.Errorf("could not determine host IP addresses")
	// }

	serverOpts := applyServerOpts(opts...)

	return &Server{
		conn:    conn,
		ttl:     serverOpts.ttl,
		service: entry,
	}, nil
}

// RegisterProxy registers a service proxy. This call will skip the hostname/IP lookup and
// will use the provided values.
func RegisterProxy(instance, service, domain string, port int, host string, ips []string, text []string, ifaces []net.Interface, opts ...ServerOption) (*Server, error) {
	entry := newServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text
	entry.HostName = host

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.HostName == "" {
		return nil, fmt.Errorf("missing host name")
	}
	if entry.Domain == "" {
		entry.Domain = "local"
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return nil, fmt.Errorf("failed to parse given IP: %v", ip)
		} else if ipv4 := ipAddr.To4(); ipv4 != nil {
			entry.AddrIPv4 = append(entry.AddrIPv4, ipAddr)
		} else if ipv6 := ipAddr.To16(); ipv6 != nil {
			entry.AddrIPv6 = append(entry.AddrIPv6, ipAddr)
		} else {
			return nil, fmt.Errorf("the IP is neither IPv4 nor IPv6: %#v", ipAddr)
		}
	}

	conn, err := newDualConn(ifaces, IPv4AndIPv6)
	if err != nil {
		return nil, err
	}
	serverOpts := applyServerOpts(opts...)

	return &Server{
		conn:    conn,
		ttl:     serverOpts.ttl,
		service: entry,
	}, nil
}

const (
	qClassCacheFlush uint16 = 1 << 15
)

// Server structure encapsulates both IPv4/IPv6 UDP connections
type Server struct {
	service *ServiceEntry
	conn    *dualConn
	ttl     uint32
}

func (s *Server) Serve(ctx context.Context) error {
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

func (s *Server) Close() error {
	return s.conn.Close()
}

// SetText updates and announces the TXT records
func (s *Server) SetText(text []string) {
	s.service.Text = text
	s.announceText()
}

// TTL sets the TTL for DNS replies
//
// Deprecated: This method is racy. Use the TTL server option instead.
func (s *Server) TTL(ttl uint32) {
	s.ttl = ttl
}

// recv4 is a long running routine to receive packets from an interface
func (s *Server) recv(ctx context.Context) {
	msgCh := make(chan MsgMeta, 32)
	go s.conn.RunReader(msgCh)

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-msgCh:
			_ = s.handleQuery(msg.Msg, msg.IfIndex, msg.From)
		}
	}
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, ifIndex int, from net.Addr) error {
	// Ignore questions with authoritative section for now
	if len(query.Ns) > 0 {
		return nil
	}

	// Handle each question
	var err error
	for _, q := range query.Question {
		resp := dns.Msg{}
		resp.SetReply(query)
		resp.Compress = true
		resp.RecursionDesired = false
		resp.Authoritative = true
		resp.Question = nil // RFC6762 section 6 "responses MUST NOT contain any questions"
		resp.Answer = []dns.RR{}
		resp.Extra = []dns.RR{}
		if err = s.handleQuestion(q, &resp, query); err != nil {
			// log.Printf("[ERR] zeroconf: failed to handle question %v: %v", q, err)
			continue
		}
		// Check if there is an answer
		if len(resp.Answer) == 0 {
			continue
		}

		if isUnicastQuestion(q) {
			// Send unicast
			if e := s.conn.WriteUnicast(&resp, ifIndex, from); e != nil {
				err = e
			}
		} else {
			// Send mulicast
			if e := s.conn.WriteMulticast(&resp, ifIndex, from); e != nil {
				err = e
			}
		}
	}

	return err
}

// RFC6762 7.1. Known-Answer Suppression
func isKnownAnswer(resp *dns.Msg, query *dns.Msg) bool {
	if len(resp.Answer) == 0 || len(query.Answer) == 0 {
		return false
	}

	if resp.Answer[0].Header().Rrtype != dns.TypePTR {
		return false
	}
	answer := resp.Answer[0].(*dns.PTR)

	for _, known := range query.Answer {
		hdr := known.Header()
		if hdr.Rrtype != answer.Hdr.Rrtype {
			continue
		}
		ptr := known.(*dns.PTR)
		if ptr.Ptr == answer.Ptr && hdr.Ttl >= answer.Hdr.Ttl/2 {
			// log.Printf("skipping known answer: %v", ptr)
			return true
		}
	}

	return false
}

// handleQuestion is used to handle an incoming question
func (s *Server) handleQuestion(q dns.Question, resp *dns.Msg, query *dns.Msg) error {
	if s.service == nil {
		return nil
	}

	switch q.Name {
	case s.service.ServiceTypeName():
		s.serviceTypeName(resp, s.ttl)
		if isKnownAnswer(resp, query) {
			resp.Answer = nil
		}

	case s.service.ServiceName():
		s.composeBrowsingAnswers(resp)
		if isKnownAnswer(resp, query) {
			resp.Answer = nil
		}

	case s.service.ServiceInstanceName():
		s.composeLookupAnswers(resp, s.ttl, false)
	default:
		// handle matching subtype query
		for _, subtype := range s.service.Subtypes {
			subtype = fmt.Sprintf("%s._sub.%s", subtype, s.service.ServiceName())
			if q.Name == subtype {
				s.composeBrowsingAnswers(resp)
				if isKnownAnswer(resp, query) {
					resp.Answer = nil
				}
				break
			}
		}
	}

	return nil
}

func (s *Server) composeBrowsingAnswers(resp *dns.Msg) {
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Ptr: s.service.ServiceInstanceName(),
	}
	resp.Answer = append(resp.Answer, ptr)

	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	resp.Extra = append(resp.Extra, srv)

	if s.service.Text != nil {
		txt := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   s.service.ServiceInstanceName(),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    s.ttl,
			},
			Txt: s.service.Text,
		}
		resp.Extra = append(resp.Extra, txt)
	}

	resp.Extra = s.appendAddrs(resp.Extra, s.ttl, false)
}

func (s *Server) composeLookupAnswers(resp *dns.Msg, ttl uint32, flushCache bool) {
	// From RFC6762
	//    The most significant bit of the rrclass for a record in the Answer
	//    Section of a response message is the Multicast DNS cache-flush bit
	//    and is discussed in more detail below in Section 10.2, "Announcements
	//    to Flush Outdated Cache Entries".
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceInstanceName(),
	}
	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	dnssd := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceTypeName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceName(),
	}
	resp.Answer = append(resp.Answer, srv, ptr, dnssd)

	if s.service.Text != nil {
		txt := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   s.service.ServiceInstanceName(),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET | qClassCacheFlush,
				Ttl:    ttl,
			},
			Txt: s.service.Text,
		}
		resp.Answer = append(resp.Answer, txt)
	}

	for _, subtype := range s.service.Subtypes {
		resp.Answer = append(resp.Answer,
			&dns.PTR{
				Hdr: dns.RR_Header{
					Name:   subtype,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Ptr: s.service.ServiceInstanceName(),
			})
	}

	resp.Answer = s.appendAddrs(resp.Answer, ttl, flushCache)
}

func (s *Server) serviceTypeName(resp *dns.Msg, ttl uint32) {
	// From RFC6762
	// 9.  Service Type Enumeration
	//
	//    For this purpose, a special meta-query is defined.  A DNS query for
	//    PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
	//    set of PTR records, where the rdata of each PTR record is the two-
	//    label <Service> name, plus the same domain, e.g.,
	//    "_http._tcp.<Domain>".
	dnssd := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceTypeName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceName(),
	}
	resp.Answer = append(resp.Answer, dnssd)
}

// Perform probing & announcement
func (s *Server) announce(ctx context.Context) error {
	// TODO: implement a proper probing & conflict resolution

	// From RFC6762
	//    The Multicast DNS responder MUST send at least two unsolicited
	//    responses, one second apart. To provide increased robustness against
	//    packet loss, a responder MAY send up to eight unsolicited responses,
	//    provided that the interval between unsolicited responses increases by
	//    at least a factor of two with every response sent.

	timeout := time.Second
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	// TODO: make response authoritative if we are the publisher
	resp.Compress = true
	resp.Answer = []dns.RR{}
	resp.Extra = []dns.RR{}
	s.composeLookupAnswers(resp, s.ttl, true)
	for i := 0; i < multicastRepetitions; i++ {
		if err := s.conn.WriteMulticastAll(resp); err != nil {
			log.Printf("[ERR] zeroconf: failed to send announcement: %v\n", err)
		}
		if err := sleepContext(ctx, timeout); err != nil {
			return err
		}
		timeout *= 2
	}
	return nil
}

// announceText sends a Text announcement with cache flush enabled
func (s *Server) announceText() {
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    s.ttl,
		},
		Txt: s.service.Text,
	}

	resp.Answer = []dns.RR{txt}
	s.conn.WriteMulticastAll(resp)
}

func (s *Server) unregister() error {
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	resp.Answer = []dns.RR{}
	resp.Extra = []dns.RR{}
	s.composeLookupAnswers(resp, 0, true)
	return s.conn.WriteMulticastAll(resp)
}

func (s *Server) appendAddrs(list []dns.RR, ttl uint32, flushCache bool) []dns.RR {
	v4 := s.service.AddrIPv4
	v6 := s.service.AddrIPv6
	var cacheFlushBit uint16
	if flushCache {
		cacheFlushBit = qClassCacheFlush
	}
	for _, ipv4 := range v4 {
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   s.service.HostName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET | cacheFlushBit,
				Ttl:    ttl,
			},
			A: ipv4,
		}
		list = append(list, a)
	}
	for _, ipv6 := range v6 {
		aaaa := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   s.service.HostName,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET | cacheFlushBit,
				Ttl:    ttl,
			},
			AAAA: ipv6,
		}
		list = append(list, aaaa)
	}
	return list
}

func isUnicastQuestion(q dns.Question) bool {
	// From RFC6762
	// 18.12.  Repurposing of Top Bit of qclass in Question Section
	//
	//    In the Question Section of a Multicast DNS query, the top bit of the
	//    qclass field is used to indicate that unicast responses are preferred
	//    for this particular question.  (See Section 5.4.)
	return q.Qclass&qClassCacheFlush != 0
}
