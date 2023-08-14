package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// RFC6762 Section 8.3: The Multicast DNS responder MUST send at least two unsolicited
	// responses
	announceCount = 2
)

type Config struct {
	// IP protocol to use, default = IPv4AndIPv6
	IPType IPType

	// Interfaces to use for mDNS, by default all multicast-enabled interfaces
	Interfaces []net.Interface

	// While browsing, artificially shorten the life-time of them if their advertised TTL is higher,
	// which helps detect services that disappear more promptly. Note that this results in more
	// frequent "live-check" queries. If zero, the default will be 75 min.
	MaxAge time.Duration

	// Server TXT entry
	Text []string

	// Server hostname, default = os.Hostname()
	Hostname string

	// Client and server domain, this should rarely be changed. default = "local"
	Domain string
}

var defaultHostname, _ = os.Hostname()

func (c *Config) ipType() IPType {
	if c.IPType == 0 {
		return IPv4AndIPv6
	}
	return c.IPType
}

func (c *Config) maxAge() time.Duration {
	if c.MaxAge == 0 {
		return time.Minute * 75
	}
	return max(5*time.Second, c.MaxAge)
}

func (c *Config) domain() string {
	if c.Domain == "" {
		return "local"
	}
	return c.Domain
}

func (c *Config) hostname() string {
	// TODO: Likely prone to conflicts and domain-name unfriendly, potentially generate and sanitize
	if c.Hostname == "" {
		return fmt.Sprintf("%v.%v", defaultHostname, "local")
	}
	return c.Hostname
}

// Register a service by given arguments. This call will take the system's hostname
// and lookup IP by that hostname.
//
// Service name should be on the form `_my-service._tcp` or `_my-service._udp`
//
// The service string may include subtypes, e.g. `_my-service._tcp,_printer,_ipp`
func Register(instance, serviceStr string, port uint16, conf *Config) (*Server, error) {
	if conf == nil {
		conf = new(Config)
	}

	service, subtypes := parseSubtypes(serviceStr)
	entry := newServiceEntry(instance, service, conf.domain(), subtypes)
	entry.Port = port
	entry.Text = conf.Text

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.Domain == "" {
		entry.Domain = "local"
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	var err error
	entry.Hostname = conf.hostname()
	if err != nil {
		return nil, fmt.Errorf("could not determine host")
	}

	if !strings.HasSuffix(trimDot(entry.Hostname), entry.Domain) {
		entry.Hostname = fmt.Sprintf("%s.%s.", trimDot(entry.Hostname), trimDot(entry.Domain))
	}

	conn, err := newDualConn(conf.Interfaces, conf.ipType())
	if err != nil {
		return nil, err
	}

	entry.AddrIPv4, entry.AddrIPv6 = conn.Addrs()

	if entry.AddrIPv4 == nil && entry.AddrIPv6 == nil {
		conn.Close()
		return nil, fmt.Errorf("could not determine host IP addresses")
	}

	return &Server{
		conn:    conn,
		service: entry,
		records: recordsFromService(entry, false),
	}, nil
}

// RegisterProxy registers a service proxy. This call will skip the hostname/IP lookup and
// will use the provided values.
func RegisterProxy(instance, serviceStr string, port uint16, host string, ips []string, conf *Config) (*Server, error) {
	if conf == nil {
		conf = new(Config)
	}
	service, subtypes := parseSubtypes(serviceStr)
	entry := newServiceEntry(instance, service, conf.domain(), subtypes)
	entry.Port = port
	entry.Text = conf.Text
	entry.Hostname = conf.hostname()

	// TODO: Don't repeat these checks, instead provide a ServiceEntry as argument
	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.Hostname == "" {
		return nil, fmt.Errorf("missing host name")
	}
	if entry.Domain == "" {
		entry.Domain = "local"
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	if !strings.HasSuffix(trimDot(entry.Hostname), entry.Domain) {
		entry.Hostname = fmt.Sprintf("%s.%s.", trimDot(entry.Hostname), trimDot(entry.Domain))
	}

	for _, ip := range ips {
		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("failed to parse given IP: %v", ip)
		} else if ipAddr.Is4() {
			entry.AddrIPv4 = append(entry.AddrIPv4, ipAddr)
		} else if ipAddr.Is6() {
			entry.AddrIPv6 = append(entry.AddrIPv6, ipAddr)
		} else {
			return nil, fmt.Errorf("the IP is neither IPv4 nor IPv6: %#v", ipAddr)
		}
	}

	conn, err := newDualConn(conf.Interfaces, conf.IPType)
	if err != nil {
		return nil, err
	}

	return &Server{
		conn:    conn,
		service: entry,
		records: recordsFromService(entry, false),
	}, nil
}

// Server structure encapsulates both IPv4/IPv6 UDP connections
type Server struct {
	service *ServiceEntry
	conn    *dualConn
	records []dns.RR
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

// recv4 is a long running routine to receive packets from an interface
func (s *Server) recv(ctx context.Context) {
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

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, ifIndex int, from net.Addr) (err error) {
	// RFC6762 Section 8.2: Probing messages are ignored, for now.
	if len(query.Ns) > 0 {
		return nil
	}

	// RFC6762 Section 5.2: Multiple questions in the same message are responded to individually.
	for _, q := range query.Question {

		// Check that
		resp := dns.Msg{}
		resp.SetReply(query)
		resp.Compress = true
		resp.RecursionDesired = false
		resp.Authoritative = true
		resp.Question = nil // RFC6762 Section 6: "responses MUST NOT contain any questions"

		resp.Answer = answerTo(s.records, query.Answer, q)
		if len(resp.Answer) == 0 {
			continue
		}
		resp.Extra = extraRecords(s.records, resp.Answer)

		if q.Qclass&qClassUnicastResponse != 0 {
			err = s.conn.WriteUnicast(&resp, ifIndex, from)
		} else {
			err = s.conn.WriteMulticast(&resp, ifIndex, from)
		}
	}

	return err
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
	resp.MsgHdr.Authoritative = true
	resp.Compress = true
	resp.Answer = append(resp.Answer, s.records...)
	for i := 0; i < announceCount; i++ {
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

func (s *Server) unregister() error {
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	resp.Compress = true
	resp.Answer = recordsFromService(s.service, true)
	return s.conn.WriteMulticastAll(resp)
}
