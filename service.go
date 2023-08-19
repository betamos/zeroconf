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

// Service contains the basic description of a service.
// It is used both in responding and enumerating.
type Service struct {

	// Service name, e.g. "_http._tcp"
	Type string `json:"type"`

	// Service subtypes, e.g. "_printer". If enumerating, only zero or one subtype is allowed.
	// See RFC 6763 Section 7.1.
	Subtypes []string `json:"subtypes"`

	// Domain should be "local" for mDNS
	Domain string `json:"domain"`
}

// Takes a service string on the form _type._proto(.domain)? and turns it into a service.
// Should be validated afterwards.
func parseService(service string) *Service {
	typeParts := strings.Split(service, ",")
	s := &Service{
		Type:     typeParts[0],
		Subtypes: typeParts[1:],
	}
	pathParts := strings.Split(typeParts[0], ".")
	i := min(2, len(pathParts))
	s.Type = strings.Join(pathParts[0:i], ".")
	s.Domain = strings.Join(pathParts[i:], ".")
	if s.Domain == "" {
		s.Domain = "local"
	}
	return s
}

// Equality *without* subtypes
func (s *Service) Equal(o *Service) bool {
	return s.Type == o.Type && s.Domain == o.Domain
}

func (s *Service) normalize() {
	s.Type = strings.ToLower(s.Type)
	s.Domain = strings.ToLower(s.Domain)
	for i, subtype := range s.Subtypes {
		s.Subtypes[i] = strings.ToLower(subtype)
	}
	slices.Sort(s.Subtypes)
	slices.Compact(s.Subtypes)
}

func (s *Service) Validate() error {
	s.normalize()
	if labels, ok := dns.IsDomainName(s.Type); !ok || labels != 2 {
		return fmt.Errorf("invalid service [%s] needs to be dot-separated", s.Type)
	}
	if _, ok := dns.IsDomainName(s.Domain); !ok {
		return fmt.Errorf("invalid domain [%s]", s.Domain)
	}
	for _, subtype := range s.Subtypes {
		if labels, ok := dns.IsDomainName(s.Domain); !ok || labels != 1 {
			return fmt.Errorf("invalid subtype [%s]", subtype)
		}
	}
	return nil
}

// Returns the main service type, "_http._tcp.local." and any additional subtypes,
// e.g. "_printer._sub._http._tcp.local.". Responders only.
//
// # See RFC6763 Section 7.1
//
// Format:
// <instance>.<service>.<domain>.
// <instance>._sub.<subtype>.<service>.<domain>.
func (s *Service) responderNames() (types []string) {
	types = append(types, fmt.Sprintf("%s.%s.", s.Type, s.Domain))
	for _, sub := range s.Subtypes {
		types = append(types, fmt.Sprintf("%s._sub.%s.%s.", sub, s.Type, s.Domain))
	}
	return
}

// Returns the query DNS name to use in e.g. a PTR query, and whether the query is a instance
// resolve query or not.
func (s *Service) queryName() (str string) {
	if len(s.Subtypes) > 0 {
		return fmt.Sprintf("%s._sub.%s.%s.", s.Subtypes[0], s.Type, s.Domain)
	} else {
		return fmt.Sprintf("%s.%s.", s.Type, s.Domain)
	}
}

// Returns a complete service instance path, e.g. `MyDemo\ Service._foobar._tcp.local.`,
// which is composed from service instance name, service name and a domain.
func instancePath(s *Service, e *ServiceEntry) string {
	return fmt.Sprintf("%s.%s.%s.", e.escapeName(), s.Type, s.Domain)
}

// Parse an instance path
func parseInstancePath(s string) (service *Service, instance string, err error) {
	parts := dns.SplitDomainName(s)
	// ["_sub", subtype, ...]
	var subtypes []string
	// [instance, service-id, service-proto, domain...]
	if len(parts) < 4 {
		return nil, "", fmt.Errorf("not enough components")
	}
	// 4.3.  Internal Handling of Names says that instance name may contain dots.
	instance = unescapeDns(parts[0])
	ty := fmt.Sprintf("%s.%s", parts[1], parts[2])
	domain := strings.Join(parts[3:], ".")
	service = &Service{ty, subtypes, domain}
	if err := service.Validate(); err != nil {
		return nil, "", err
	}
	return service, instance, nil
}

// ServiceEntry represents a browse/lookup result for client API.
// It is also used to configure service registration (server API), which is
// used to answer multicast queries.
type ServiceEntry struct {
	// Instance name, e.g. `Mr. Office Printer`  (avoid backslash)
	Name string `json:"name"`

	// Port number, must be positive
	Port uint16 `json:"port"`

	// Optional additional text (avoid backslash)
	Text []string `json:"text"`

	// Hostname, e.g. `Bryans-Mac.local`
	Hostname string `json:"hostname"`

	// IP addresses
	Addrs []netip.Addr `json:"addrs"`

	// Internal expiry info used by cache
	ttl    uint32
	seenAt time.Time
}

func (s *ServiceEntry) String() string {
	return fmt.Sprintf("%v (%v)", s.Name, s.Hostname)
}

func (s *ServiceEntry) Validate() error {
	if s.Hostname == "" {
		return errors.New("no instance specified")
	}
	if s.Hostname == "" {
		return errors.New("no hostname specified")
	}
	if s.Port == 0 {
		return errors.New("port is 0")
	}
	return nil
}

func (s *ServiceEntry) hostname() string {
	return fmt.Sprintf("%v.", s.Hostname)
}

func (s *ServiceEntry) Equal(o *ServiceEntry) bool {
	if s.Hostname != o.Hostname || s.Port != o.Port || !slices.Equal(s.Text, o.Text) {
		return false
	}
	// Note we're not sorting ("normalizing") addresses, since the order can indicate preference
	return slices.Equal(s.Addrs, o.Addrs)
}

// RFC 6763 Section 4.3: [...] the <Instance> portion is allowed to contain any characters
// Spaces and backslashes are escaped by "github.com/miekg/dns".
func (s *ServiceEntry) escapeName() string {
	return strings.ReplaceAll(s.Name, ".", "\\.")
}
