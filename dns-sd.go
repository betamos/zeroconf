package zeroconf

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/miekg/dns"
)

// This file implements DNS Service Discovery from RFC 6763

// instance: any < 63 characters
// service: dot-separated identifier, e.g. `_http._tcp` (must be `_tcp` or `_udp`)
// domain: typically `local`, but may in theory be an FQDN, e.g. `example.org`
// subtype: optional service sub-type, e.g. `_printer`
// hostname: hostname of a device, e.g. `Bryans-PC.local`
//
// Strings used in mDNS:
//
// target: <instance> . <service> . <domain>, e.g. `Bryan's Service._http._tcp.local`
// query: <service> . <domain>, e.g. `_http._tcp.local`
// sub-query: <subtype> . `_sub` . <service> . <domain>, e.g. `_printer._sub._http._tcp.local`
// meta-query: `_services._dns-sd._udp.local`

// We implement the following PTR queries:
//
// PTR <query>       ->  <target>               // Service enumeration
// PTR <sub-query>   ->  <target>               // Service enumeration restricted to a subtype
// PTR <meta-query>  ->  <service> . <domain>   // Meta-service enumeration
//
// The PTR target refers to the SRV and TXT records:
//
// SRV <target>:
//   Hostname: <hostname>
//   Port: <...>
//
// TXT <target>: (note this is included as an empty list even if no txt is provided)
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
// All of the "referred" records are added to the answer's additional section.

// Each DNS packet is considered separately, and has a single response packet.
// Multiple questions are allowed and are all answered separately but within
// a single response packet. The response packet has no questions.
// PTR questions without answer are ignored.

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

// Return a single service instance from the msg that matches the "search record" provided.
// Typically, the search record is a "browsing" record for a service (i.e. no instance).
func serviceFromRecords(msg *dns.Msg, search *Service) (instances []*Instance) {
	// TODO: Support meta-queries
	var (
		answers  = append(msg.Answer, msg.Extra...)
		question = search.queryName()
		m        = make(map[string]*Instance, 1) // temporary map of instance paths to instances
		addrMap  = make(map[string][]netip.Addr, 1)
		instance *Instance
	)

	// PTR, then SRV + TXT, then A and AAAA. The following loop depends on it
	// Note that stable sort is necessary to preserve order of A and AAAA records
	slices.SortStableFunc(answers, byRecordType)

	for _, answer := range answers {
		switch rr := answer.(type) {
		// Phase 1: create instances
		case *dns.PTR:
			if rr.Hdr.Name != question { // match question, e.g. `_printer._sub._http._tcp.`
				continue
			}

			// pointer to instance path, e.g. `My Printer._http._tcp.`
			service, instanceName, err := parseInstancePath(rr.Ptr)
			if err == nil && search.Equal(service) {
				m[rr.Ptr] = &Instance{Name: instanceName}
			}

		// Phase 2: populate other fields
		case *dns.SRV:
			if instance = m[rr.Hdr.Name]; instance == nil {
				continue
			}
			instance.Hostname = rr.Target
			instance.Port = rr.Port
			instance.ttl = rr.Hdr.Ttl
		case *dns.TXT:
			if instance = m[rr.Hdr.Name]; instance == nil {
				continue
			}
			instance.Text = rr.Txt

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

	for _, instance := range m {
		instance.Addrs = addrMap[instance.Hostname]

		// Unescape afterwards to maintain comparison soundness above
		instance.Hostname = unescapeDns(instance.Hostname)
		for i, txt := range instance.Text {
			instance.Text[i] = unescapeDns(txt)
		}
		instance.Hostname = trimDot(instance.Hostname)
		if err := instance.Validate(); err != nil {
			continue
		}
		instances = append(instances, instance)
	}
	return
}

func recordsFromService(service *Service, instance *Instance, unannounce bool) (records []dns.RR) {

	// RFC6762 Section 10: Records referencing a hostname (SRV/A/AAAA) SHOULD use TTL of 120 s,
	// to account for network interface and IP address changes, while others should be 75 min.
	var hostRecordTTL, defaultTTL uint32 = 120, 75 * 60
	if unannounce {
		hostRecordTTL, defaultTTL = 0, 0
	}

	names := service.responderNames()
	instancePath := instancePath(service, instance)
	hostname := instance.hostname()

	// Pre-initialize length for efficiency
	records = make([]dns.RR, 0, len(names)+len(instance.Addrs)+3)

	// PTR records
	for _, name := range names {
		records = append(records, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypePTR,
				Class:  sharedRecordClass,
				Ttl:    defaultTTL,
			},
			Ptr: instancePath,
		})
	}

	// RFC 6763 Section 9: Service Type Enumeration.
	// For this purpose, a special meta-query is defined.  A DNS query for
	// PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
	// set of PTR records, where the rdata of each PTR record is the two-
	// label <Service> name, plus the same domain, e.g., "_http._tcp.<Domain>".
	records = append(records, &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_services._dns-sd._udp.%v.", service.Domain),
			Rrtype: dns.TypePTR,
			Class:  sharedRecordClass,
			Ttl:    defaultTTL,
		},
		Ptr: fmt.Sprintf("%v.%v.", service.Type, service.Domain),
	})

	// SRV record
	records = append(records, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   instancePath,
			Rrtype: dns.TypeSRV,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		Port:   instance.Port,
		Target: hostname,
	})

	// TXT record
	records = append(records, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   instancePath,
			Rrtype: dns.TypeTXT,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		Txt: instance.Text,
	})

	// NSEC for SRV, TXT
	// See RFC 6762 Section 6.1: Negative Responses
	records = append(records, &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   instancePath,
			Rrtype: dns.TypeNSEC,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		NextDomain: instancePath,
		TypeBitMap: []uint16{dns.TypeTXT, dns.TypeSRV},
	})

	// A and AAAA records
	for _, addr := range instance.Addrs {
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

// Compare records by type for indirection order of DNS-SD
func byRecordType(a, b dns.RR) int {
	return recordOrder(a) - recordOrder(b)
}

func recordOrder(rr dns.RR) int {
	switch rr.Header().Rrtype {
	case dns.TypePTR: // Points at SRV, TXT
		return 0
	case dns.TypeSRV, dns.TypeTXT: // Points at A, AAAA
		return 1
	case dns.TypeA, dns.TypeAAAA:
		return 2
	}
	return 3
}
