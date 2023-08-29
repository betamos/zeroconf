package zeroconf

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// A service type which identifies an application or protocol, e.g. a http server, printer or an IoT
// device.
type Type struct {

	// Service type name, on the form `_my-service._tcp` or `_my-service._udp`
	Name string `json:"type"`

	// Service subtypes, e.g. `_printer`. A service can be published with multiple subtypes.
	// While browsing, a single subtype can be specified to narrow the query.
	// See RFC 6763 Section 7.1.
	Subtypes []string `json:"subtypes"`

	// Domain should be `local`
	Domain string `json:"domain"`
}

func (t *Type) String() string {
	var sub string
	if len(t.Subtypes) > 0 {
		sub = "," + strings.Join(t.Subtypes, ",")
	}
	return fmt.Sprintf("%s.%s%s", t.Name, t.Domain, sub)
}

// Returns a type based on a string on the form `_my-service._tcp` or `_my-service._udp`.
//
// The domain is `local` by default, but can be specified explicitly. Finally, a comma-
// separated list of subtypes can be added at the end. Here is a full example:
//
// `_my-service._tcp.custom.domain,_printer,_sub1,_sub2`
func NewType(typeStr string) *Type {
	typeParts := strings.Split(typeStr, ",")
	ty := &Type{
		Name:     typeParts[0],
		Subtypes: typeParts[1:],
	}
	pathParts := strings.Split(typeParts[0], ".")
	i := min(2, len(pathParts))
	ty.Name = strings.Join(pathParts[0:i], ".")
	ty.Domain = strings.Join(pathParts[i:], ".")
	if ty.Domain == "" {
		ty.Domain = "local"
	}
	return ty
}

// Returns true if the types are equal (excluding subtypes)
func (s *Type) Equal(o *Type) bool {
	if s == o {
		return true
	}
	return s.Name == o.Name && s.Domain == o.Domain
}

func (s *Type) normalize() {
	s.Name = strings.ToLower(s.Name)
	s.Domain = strings.ToLower(s.Domain)
	for i, subtype := range s.Subtypes {
		s.Subtypes[i] = strings.ToLower(subtype)
	}
	slices.Sort(s.Subtypes)
	slices.Compact(s.Subtypes)
}

func (s *Type) Validate() error {
	s.normalize()
	if labels, ok := dns.IsDomainName(s.Name); !ok || labels != 2 {
		return fmt.Errorf("invalid service [%s] needs to be dot-separated", s.Name)
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

// A service reachable on the local network.
type Service struct {
	// The service type
	Type *Type

	// A name that uniquely identifies a service of a given type, e.g. `Office Printer 32`.
	Name string `json:"name"`

	// A non-zero port number
	Port uint16 `json:"port"`

	// A hostname, e.g. `Bryans-Mac.local`
	Hostname string `json:"hostname"`

	// A set of IP addresses
	Addrs []netip.Addr `json:"addrs"`

	// Optional additional data
	Text []string `json:"text"`

	// Internal expiry data
	ttl    time.Duration
	seenAt time.Time
}

// Create a new service for publishing. The hostname is generated based on `os.Hostname()`.
// Choose a unique name to avoid conflicts with other services of the same type.
func NewService(ty *Type, name string, port uint16) *Service {
	osHostname, _ := os.Hostname()
	return &Service{
		Type:     ty,
		Name:     name,
		Port:     port,
		Hostname: ensureSuffix(osHostname, ".local"),
	}
}

func (s *Service) String() string {
	return fmt.Sprintf("%v (%v)", s.Name, s.Hostname)
}

func (s *Service) Validate() error {
	if s.Type == nil {
		return errors.New("no type specified")
	}
	if err := s.Type.Validate(); err != nil {
		return err
	}
	if s.Name == "" {
		return errors.New("no name specified")
	}
	if s.Hostname == "" {
		return errors.New("no hostname specified")
	}
	return nil
}

// Returns true if the services have the same identity, meaning they have the same type (excluding
// subtypes) and service name.
func (s *Service) Same(o *Service) bool {
	if s == o {
		return true
	}
	return s.Type.Equal(o.Type) && s.Name == o.Name
}

// Returns true if the type (excluding subtypes) and all fields are equal.
func (s *Service) Equal(o *Service) bool {
	if s == o {
		return true
	}
	if !s.Type.Equal(o.Type) {
		return false
	}
	if s.Name != o.Name || s.Hostname != o.Hostname || s.Port != o.Port || !slices.Equal(s.Text, o.Text) {
		return false
	}
	// Note we're not "normalizing" addrs here
	return slices.Equal(s.Addrs, o.Addrs)
}
