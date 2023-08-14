package zeroconf

import (
	"fmt"
	"net/netip"

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

// Returns the answers to a question and a known-answer list
func answerTo(records, knowns []dns.RR, question dns.Question) (answers []dns.RR) {
	for _, record := range records {
		if isAnswerTo(record, question) && !isKnownAnswer(record, knowns) {
			answers = append(answers, record)
		}
	}
	return
}

// Returns any records that are considered additional to any answer where:
//
// (1) All SRV and TXT record(s) named in a PTR's rdata and
// (2) All A and AAAA record(s) named in an SRV's rdata.
//
// This is transitive, such that a PTR answer "generates" all other record types.
//
// RFC6762 7.1. DNS Additional Record Generation.
func extraRecords(records, answers []dns.RR) (extras []dns.RR) {
ptrLoop:
	for _, record := range records {
		recordHdr := record.Header()
		if !(recordHdr.Rrtype == dns.TypeSRV || recordHdr.Rrtype == dns.TypeTXT) {
			continue
		}
		for _, answer := range answers {
			if ptr, ok := answer.(*dns.PTR); ok && ptr.Ptr == recordHdr.Name {
				extras = append(extras, record)
				continue ptrLoop
			}
		}
	}
	// Invariant: extras contain SRV and TXT records

	// For transitivity, add the already generated records to the "search set"
	answers = append(answers, extras...)

srvLoop:
	for _, record := range records {
		recordHdr := record.Header()
		if !(recordHdr.Rrtype == dns.TypeA || recordHdr.Rrtype == dns.TypeAAAA) {
			continue
		}
		for _, answer := range answers {
			if srv, ok := answer.(*dns.SRV); ok && srv.Target == recordHdr.Name {
				extras = append(extras, record)
				continue srvLoop
			}
		}
	}
	return
}

// Return a single service entry from the msg that matches the "search record" provided.
// Typically, the search record is a "browsing" record for a service (i.e. no instance).
func serviceFromRecords(msg *dns.Msg, search *ServiceRecord) *ServiceEntry {
	// TODO: Support meta-queries
	// TODO: Support multiple entries, possibly using extraRecords
	var (
		answers     = append(msg.Answer, msg.Extra...)
		question, _ = search.queryName()
		ptrTo       string
		srv         *dns.SRV
	)

	for _, answer := range answers {
		switch rr := answer.(type) {
		case *dns.PTR:
			if rr.Hdr.Name == question {
				ptrTo = rr.Ptr
			}
		case *dns.SRV:
			srv = rr
		}
	}
	if srv == nil || ptrTo != srv.Hdr.Name {
		return nil
	}

	// TODO: Verify that the parsed entry matches the query.
	record := parseServiceRecord(srv.Hdr.Name)
	if record == nil {
		return nil
	}
	entry := &ServiceEntry{
		ServiceRecord: record,
		Hostname:      trimDot(srv.Target), // TODO: Unescape hostname
		Port:          srv.Port,
		ttl:           srv.Hdr.Ttl,
	}

	for _, answer := range answers {

		switch rr := answer.(type) {
		case *dns.TXT:
			if rr.Hdr.Name == srv.Hdr.Name {
				entry.Text = rr.Txt
			}
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(rr.A); rr.Hdr.Name == srv.Target && ok {
				entry.Addrs = append(entry.Addrs, ip.Unmap())
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(rr.AAAA); rr.Hdr.Name == srv.Target && ok {
				entry.Addrs = append(entry.Addrs, ip)
			}
		}
	}
	entry.normalize()
	return entry
}

func recordsFromService(entry *ServiceEntry, unannounce bool) (records []dns.RR) {

	// RFC6762 Section 10: Records referencing a hostname (SRV/A/AAAA) SHOULD use TTL of 120 s,
	// to account for network interface and IP address changes, while others should be 75 min.
	var hostRecordTTL, defaultTTL uint32 = 120, 75 * 60
	if unannounce {
		hostRecordTTL, defaultTTL = 0, 0
	}

	names := entry.responderNames()
	target := entry.target()
	hostname := entry.hostname()

	// Pre-initialize length for efficiency
	records = make([]dns.RR, 0, len(names)+len(entry.Addrs)+3)

	// PTR records
	for _, name := range names {
		records = append(records, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypePTR,
				Class:  sharedRecordClass,
				Ttl:    defaultTTL,
			},
			Ptr: target,
		})
	}

	// RFC 6763 Section 9: Service Type Enumeration.
	// For this purpose, a special meta-query is defined.  A DNS query for
	// PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
	// set of PTR records, where the rdata of each PTR record is the two-
	// label <Service> name, plus the same domain, e.g., "_http._tcp.<Domain>".
	records = append(records, &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_services._dns-sd._udp.%v.", entry.Domain),
			Rrtype: dns.TypePTR,
			Class:  sharedRecordClass,
			Ttl:    defaultTTL,
		},
		Ptr: fmt.Sprintf("%v.%v.", entry.Service, entry.Domain),
	})

	// SRV record
	records = append(records, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   target,
			Rrtype: dns.TypeSRV,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		Port:   entry.Port,
		Target: hostname,
	})

	// TXT record
	records = append(records, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   target,
			Rrtype: dns.TypeTXT,
			Class:  uniqueRecordClass,
			Ttl:    defaultTTL,
		},
		Txt: entry.Text,
	})

	// A and AAAA records
	for _, addr := range entry.Addrs {
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
	return
}
