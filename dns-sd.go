package zeroconf

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RFC 6763: DNS Service Discovery
//
// service: name of the service (aka instance), any < 63 characters
// type: two-label service type, e.g. `_http._tcp` (last label should be `_tcp` or `_udp`)
// domain: typically `local`, but may in theory be an FQDN, e.g. `example.org`
// subtype: optional service sub-type, e.g. `_printer`
// hostname: hostname of a device, e.g. `Bryans-PC.local`
//
// Names used in DNS records:
//
// service-path: <service> . <type> . <domain>, e.g. `Bryan's Service._http._tcp.local`
// query: <type> . <domain>, e.g. `_http._tcp.local`
// sub-query: <subtype> . `_sub` . <type> . <domain>, e.g. `_printer._sub._http._tcp.local`
// meta-query: `_services._dns-sd._udp.local`

// A responder should resolve the following PTR queries:
//
// PTR <query>       ->  <service-path>      // Service enumeration
// PTR <sub-query>   ->  <service-path>      // Service enumeration by subtype
// PTR <meta-query>  ->  <type> . <domain>   // Meta-service enumeration
//
// The PTR target refers to the SRV and TXT records:
//
// SRV <service-path>:
//   Hostname: <hostname>
//   Port: <...>
//
// TXT <service-path>: (note this is included as an empty list even if no txt is provided)
//   Txt: <txt>
//
// And finally, the SRV refers to the A and AAAA records:
//
// A <hostname>:
//   A: <ipv4>
//
// AAAA <hostname>:
//   AAAA: <ipv6>
//
// Optional: NSEC records, indicating that an RRSet is exhaustive.
//
// Note that all "referred" records (i.e. the transitive closure) should be included in a response,
// as additional records, in order to avoid successive queries. A responder ignores any queries for
// which it doesn't have an answer.

const (
	// RFC 6762 Section 10.2: [...] the host sets the most significant bit of the rrclass
	// field of the resource record.  This bit, the cache-flush bit, tells neighboring hosts that
	// this is not a shared record type.
	classCacheFlush = 1 << 15

	// RFC 6762 Section 18.12: In the Question Section of a Multicast DNS query, the top bit of the
	// qclass field is used to indicate that unicast responses are preferred for this particular
	// question.
	qClassUnicastResponse = 1 << 15

	// RFC6762 Section 10: PTR service records are shared, while others (SRV/TXT/A/AAAA) are unique.
	uniqueRecordClass = dns.ClassINET | classCacheFlush
	sharedRecordClass = dns.ClassINET
)

// Returns the main service type, e.g. `_http._tcp.local.` and any additional subtypes,
// e.g. `_printer._sub._http._tcp.local.`. Responders only.
//
// # See RFC6763 Section 7.1
//
// Format:
// <type>.<domain>.
// _sub.<subtype>.<type>.<domain>.
func responderNames(ty Type) (types []string) {
	types = append(types, fmt.Sprintf("%s.%s.", ty.Name, ty.Domain))
	for _, sub := range ty.Subtypes {
		types = append(types, fmt.Sprintf("%s._sub.%s.%s.", sub, ty.Name, ty.Domain))
	}
	return
}

// Returns the query DNS name to use in e.g. a PTR query.
func queryName(ty Type) (str string) {
	if len(ty.Subtypes) > 0 {
		return fmt.Sprintf("%s._sub.%s.%s.", ty.Subtypes[0], ty.Name, ty.Domain)
	} else {
		return fmt.Sprintf("%s.%s.", ty.Name, ty.Domain)
	}
}

// Returns a complete service path, e.g. `MyDemo\ Service._foobar._tcp.local.`,
// which is composed from service name, its main type and a domain.
//
// RFC 6763 Section 4.3: [...] the <Instance> portion is allowed to contain any characters
// Spaces and backslashes are escaped by "github.com/miekg/dns".
func servicePath(svc *Service) string {
	name := strings.ReplaceAll(svc.Name, ".", "\\.")
	return fmt.Sprintf("%s.%s.%s.", name, svc.Type.Name, svc.Type.Domain)
}

// Parse a service path into a service type and its name
// E.g. `Jessica._chat._tcp.local.`
func parseServicePath(s string) (svc *Service, err error) {
	parts := dns.SplitDomainName(s)
	// [service, type-identifier, type-proto, domain...]
	if len(parts) < 4 {
		return nil, fmt.Errorf("not enough components")
	}
	// The service name may contain dots.
	name := unescapeDns(parts[0])
	typeName := fmt.Sprintf("%s.%s", parts[1], parts[2])
	domain := strings.Join(parts[3:], ".")
	ty := Type{typeName, domain, nil}
	if err := ty.Validate(); err != nil {
		return nil, err
	}
	return &Service{Type: ty, Name: name}, nil
}

// Parse a query into a service type and its name
// E.g. `_chat._tcp.local.` or `_emoji._sub._chat._tcp.local.`
func parseQueryName(s string) (ty *Type, err error) {
	parts := dns.SplitDomainName(s)
	var subtypes []string
	// [service, type-identifier, type-proto, domain...]
	if len(parts) > 2 && parts[1] == "_sub" {
		subtypes = []string{parts[0]}
		parts = parts[2:]
	}
	if len(parts) < 3 {
		return nil, fmt.Errorf("not enough components")
	}

	typeName := fmt.Sprintf("%s.%s", parts[0], parts[1])
	domain := strings.Join(parts[2:], ".")
	ty = &Type{typeName, domain, subtypes}
	if err := ty.Validate(); err != nil {
		return nil, err
	}
	return ty, nil
}

// Returns true if the record is an answer to question
func isAnswerTo(record dns.RR, question dns.Question) bool {
	hdr := record.Header()
	return (question.Qclass == dns.TypeANY || question.Qclass == hdr.Class) && question.Name == hdr.Name
}

// Returns true if the answer is in the known-answer list, and has more than 1/2 ttl remaining.
//
// RFC6762 7.1. Known-Answer Suppression.
func isKnownAnswer(answer dns.RR, knowns []dns.RR) bool {
	answerTtl := answer.Header().Ttl
	for _, known := range knowns {
		if dns.IsDuplicate(answer, known) && known.Header().Ttl >= answerTtl/2 {
			return true
		}
	}
	return false
}

// Returns answers and "extra records" that are considered additional to any answer where:
//
// (1) All SRV and TXT record(s) named in a PTR's rdata and
// (2) All A and AAAA record(s) named in an SRV's rdata.
//
// This is transitive, such that a PTR answer "generates" all other record types.
//
// RFC6762 7.1. DNS Additional Record Generation.
//
// Note that if there is any answer, we return *all other records* as extras.
// This is both allowed, simpler and has minimal overhead in practice.
func answerTo(records, knowns []dns.RR, question dns.Question) (answers, extras []dns.RR) {

	// Fast path without allocations, since many questions will be completely unrelated
	hasAnswers := false
	for _, record := range records {
		if isAnswerTo(record, question) {
			hasAnswers = true
			continue
		}
	}
	if !hasAnswers {
		return
	}

	// Slow path, populate answers and extras
	for _, record := range records {
		if isAnswerTo(record, question) && !isKnownAnswer(record, knowns) {
			answers = append(answers, record)
		} else {
			extras = append(extras, record)
		}
	}
	if len(answers) == 0 {
		extras = nil
	}
	return
}

// Returns any services from the msg that matches the provided search type.
func servicesFromRecords(msg *dns.Msg) (services []*Service) {
	// TODO: Support meta-queries
	var (
		answers = append(msg.Answer, msg.Extra...)
		m       = make(map[string]*Service, 1) // temporary map of service paths to services
		addrMap = make(map[string][]netip.Addr, 1)
		svc     *Service
	)
	if len(msg.Question) > 0 {
		return
	}

	// SRV, then PTR + TXT, then A and AAAA. The following loop depends on it
	// Note that stable sort is necessary to preserve order of A and AAAA records
	slices.SortStableFunc(answers, byRecordType)

	for _, answer := range answers {
		switch rr := answer.(type) {
		// Phase 1: create services
		case *dns.SRV:

			// pointer to service path, e.g. `My Printer._http._tcp.`
			if svc, _ = parseServicePath(rr.Hdr.Name); svc == nil {
				continue
			}
			svc.Hostname = rr.Target
			svc.Port = rr.Port
			svc.ttl = time.Second * time.Duration(rr.Hdr.Ttl)
			m[rr.Hdr.Name] = svc

		// Phase 2: populate subtypes and text
		case *dns.PTR:
			if svc = m[rr.Ptr]; svc == nil {
				continue
			}
			// parse type from query, e.g. `_printer._sub._http._tcp.local.`
			if ty, _ := parseQueryName(rr.Hdr.Name); ty != nil && ty.Equal(svc.Type) {
				svc.Type.Subtypes = append(svc.Type.Subtypes, ty.Subtypes...)
			}
		case *dns.TXT:
			if svc = m[rr.Hdr.Name]; svc == nil {
				continue
			}
			svc.Text = rr.Txt

		// Phase 3: add addrs to addrMap
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(rr.A); ok {
				addrMap[rr.Hdr.Name] = append(addrMap[rr.Hdr.Name], ip.Unmap())
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(rr.AAAA); ok {
				addrMap[rr.Hdr.Name] = append(addrMap[rr.Hdr.Name], ip)
			}
		}
	}

	// Phase 4: add IPs
	for _, svc := range m {
		svc.Addrs = addrMap[svc.Hostname]

		// Unescape afterwards to maintain comparison soundness above
		svc.Hostname = unescapeDns(svc.Hostname)
		for idx, txt := range svc.Text {
			svc.Text[idx] = unescapeDns(txt)
		}
		svc.Hostname = trimDot(svc.Hostname)
		if err := svc.Validate(); err != nil {
			continue
		}
		services = append(services, svc)
	}
	return
}

// Ptr records for a service
func ptrRecords(svc *Service, unannounce bool) (records []dns.RR) {
	var ttl uint32 = 75 * 60
	if unannounce {
		ttl = 0
	}
	names := responderNames(svc.Type)
	for _, name := range names {
		records = append(records, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypePTR,
				Class:  sharedRecordClass,
				Ttl:    ttl,
			},
			Ptr: servicePath(svc),
		})
	}
	return
}

func recordsFromService(svc *Service, unannounce bool) (records []dns.RR) {

	// RFC6762 Section 10: Records referencing a hostname (SRV/A/AAAA) SHOULD use TTL of 120 s,
	// to account for network interface and IP address changes, while others should be 75 min.
	var hostRecordTTL, defaultTTL uint32 = 120, 75 * 60
	if unannounce {
		hostRecordTTL, defaultTTL = 0, 0
	}

	servicePath := servicePath(svc)
	hostname := svc.Hostname + "."

	// PTR records
	records = ptrRecords(svc, unannounce)

	// RFC 6763 Section 9: Service Type Enumeration.
	// For this purpose, a special meta-query is defined.  A DNS query for
	// PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
	// set of PTR records, where the rdata of each PTR record is the two-
	// label <Service> name, plus the same domain, e.g., "_http._tcp.<Domain>".
	records = append(records, &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_services._dns-sd._udp.%v.", svc.Type.Domain),
			Rrtype: dns.TypePTR,
			Class:  sharedRecordClass,
			Ttl:    defaultTTL,
		},
		Ptr: fmt.Sprintf("%v.%v.", svc.Type.Name, svc.Type.Domain),
	})

	// SRV record
	records = append(records, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   servicePath,
			Rrtype: dns.TypeSRV,
			Class:  uniqueRecordClass,
			Ttl:    hostRecordTTL,
		},
		Port:   svc.Port,
		Target: hostname,
	})

	// TXT record
	records = append(records, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   servicePath,
			Rrtype: dns.TypeTXT,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		Txt: svc.Text,
	})

	// NSEC for SRV, TXT
	// See RFC 6762 Section 6.1: Negative Responses
	records = append(records, &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   servicePath,
			Rrtype: dns.TypeNSEC,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		NextDomain: servicePath,
		TypeBitMap: []uint16{dns.TypeTXT, dns.TypeSRV},
	})

	// A and AAAA records
	for _, addr := range svc.Addrs {
		if addr.Is4() {
			records = append(records, &dns.A{
				Hdr: dns.RR_Header{
					Name:   hostname,
					Rrtype: dns.TypeA,
					Class:  uniqueRecordClass,
					Ttl:    hostRecordTTL,
				},
				A: addr.AsSlice(),
			})
		} else if addr.Is6() {
			records = append(records, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   hostname,
					Rrtype: dns.TypeAAAA,
					Class:  uniqueRecordClass,
					Ttl:    hostRecordTTL,
				},
				AAAA: addr.AsSlice(),
			})
		}
	}

	// NSEC for A, AAAA
	records = append(records, &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   hostname,
			Rrtype: dns.TypeNSEC,
			Class:  uniqueRecordClass,
			Ttl:    hostRecordTTL,
		},
		NextDomain: hostname,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
	})
	return
}

// Compare records to aid in service construction from a record list
func byRecordType(a, b dns.RR) int {
	return recordOrder(a) - recordOrder(b)
}

func recordOrder(rr dns.RR) int {
	switch rr.Header().Rrtype {
	case dns.TypeSRV:
		return 0
	case dns.TypePTR, dns.TypeTXT:
		return 1
	case dns.TypeA, dns.TypeAAAA:
		return 2
	}
	return 3
}
