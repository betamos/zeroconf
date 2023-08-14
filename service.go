package zeroconf

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ServiceRecord contains the basic description of a service.
// It is used both in responding and enumerating.
type ServiceRecord struct {
	// Instance name, e.g. "Office Printer". If enumerating, this is blank.
	Instance string `json:"name"`

	// Service name, e.g. "_http._tcp"
	Service string `json:"service"`

	// Service subtypes, e.g. "_printer". If enumerating, only zero or one subtype is allowed.
	// See RFC 6763 Section 7.1.
	Subtypes []string `json:"subtypes"`

	// Domain should be "local" for mDNS
	Domain string `json:"domain"`
}

func newServiceEnumerationRecord(service, domain string, subtypes []string) (*ServiceRecord, error) {
	if len(subtypes) > 1 {
		return nil, errors.New("too many subtypes") // TODO: Too many subtypes
	}
	s := &ServiceRecord{
		Service:  service,
		Domain:   domain,
		Subtypes: subtypes,
	}
	return s, nil
}

func (s *ServiceRecord) Equal(o *ServiceRecord) bool {
	return s.Instance == o.Instance && s.Service == o.Service && s.Domain == o.Domain && slices.Equal(s.Subtypes, o.Subtypes)
}

// Returns the main service type, "_http._tcp.local." and any additional subtypes,
// e.g. "_printer._sub._http._tcp.local.". Responders only.
//
// # See RFC6763 Section 7.1
//
// Format:
// <instance>.<service>.<domain>.
// <instance>._sub.<subtype>.<service>.<domain>.
func (s *ServiceRecord) responderNames() (types []string) {
	types = append(types, fmt.Sprintf("%s.%s.", s.Service, s.Domain))
	for _, sub := range s.Subtypes {
		types = append(types, fmt.Sprintf("%s._sub.%s.%s.", sub, s.Service, s.Domain))
	}
	return
}

// RFC 6763 Section 4.3: [...] the <Instance> portion is allowed to contain any characters
// Spaces and backslashes are escaped by "github.com/miekg/dns".
func (s *ServiceRecord) escapeInstance() string {
	return strings.ReplaceAll(s.Instance, ".", "\\.")
}

// Returns the query DNS name to use in e.g. a PTR query, and whether the query is a instance
// resolve query or not.
func (s *ServiceRecord) queryName() (str string, resolve bool) {
	if s.Instance != "" {
		return fmt.Sprintf("%s.%s.%s.", s.escapeInstance(), s.Service, s.Domain), true
	} else if len(s.Subtypes) > 0 {
		return fmt.Sprintf("%s._sub.%s.%s.", s.Subtypes[0], s.Service, s.Domain), false
	} else {
		return fmt.Sprintf("%s.%s.", s.Service, s.Domain), false
	}
}

// ServiceInstanceName returns a complete service instance name (e.g. MyDemo\ Service._foobar._tcp.local.),
// which is composed from service instance name, service name and a domain.
func (s *ServiceRecord) target() string {
	return fmt.Sprintf("%s.%s.%s.", s.escapeInstance(), s.Service, s.Domain)
}

// Parse the service type into a record
func parseServiceRecord(s string) *ServiceRecord {
	// 4.3.  Internal Handling of Names says that instance name may contain dots. Escape!
	// TODO: Lowercase, escape dots

	parts := dns.SplitDomainName(s)
	// ["_sub", subtype, ...]
	var subtypes []string
	if len(parts) >= 2 && parts[1] == "_sub" {
		subtypes = []string{parts[0]}
		parts = parts[2:]
	}
	// [instance, service-id, service-proto, domain...]
	if len(parts) < 4 {
		return nil
	}
	instance, serviceId, serviceProto := parts[0], parts[1], parts[2]
	if !(serviceProto == "_tcp" || serviceProto == "_udp") {
		return nil
	}
	instance = strings.ReplaceAll(instance, "\\", "")
	domain := strings.Join(parts[3:], ".")
	service := fmt.Sprintf("%s.%s", serviceId, serviceProto)
	return &ServiceRecord{instance, service, subtypes, domain}
}

// ServiceEntry represents a browse/lookup result for client API.
// It is also used to configure service registration (server API), which is
// used to answer multicast queries.
type ServiceEntry struct {
	*ServiceRecord
	Hostname string       `json:"hostname"` // Host machine DNS name
	Port     uint16       `json:"port"`     // Service Port
	Text     []string     `json:"text"`     // Service info served as a TXT record
	AddrIPv4 []netip.Addr `json:"-"`        // Host machine IPv4 address
	AddrIPv6 []netip.Addr `json:"-"`        // Host machine IPv6 address
	// TODO: Why not a single set of addrs?

	// Internal expiry info used by cache
	ttl    uint32
	seenAt time.Time
}

func (s *ServiceEntry) normalize() {
	if len(s.Subtypes) == 0 {
		s.Subtypes = nil
	}
	slices.Sort(s.Subtypes)
	slices.Compact(s.Subtypes)
	slices.SortFunc(s.AddrIPv4, netip.Addr.Compare)
	slices.Compact(s.AddrIPv4)
	slices.SortFunc(s.AddrIPv6, netip.Addr.Compare)
	slices.Compact(s.AddrIPv6)
	if len(s.Text) == 0 {
		s.Text = nil
	}
}

func (s *ServiceEntry) hostname() string {
	return fmt.Sprintf("%v.", s.Hostname)
}

func (s *ServiceEntry) Equal(o *ServiceEntry) bool {
	if !s.ServiceRecord.Equal(o.ServiceRecord) {
		return false
	}
	if s.Hostname != o.Hostname || s.Port != o.Port || !slices.Equal(s.Text, o.Text) {
		return false
	}
	return slices.Equal(s.AddrIPv4, o.AddrIPv4) && slices.Equal(s.AddrIPv6, o.AddrIPv6)
}

// newServiceEntry constructs a ServiceEntry.
func newServiceEntry(instance, service string, domain string, subtypes []string) *ServiceEntry {
	return &ServiceEntry{
		ServiceRecord: &ServiceRecord{instance, service, nil, domain},
	}
}
