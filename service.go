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

func (s *Type) String() string {
	var sub string
	if len(s.Subtypes) > 0 {
		sub = "," + strings.Join(s.Subtypes, ",")
	}
	return fmt.Sprintf("%s.%s%s", s.Name, s.Domain, sub)
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

// Equality *without* subtypes
func (s *Type) Equal(o *Type) bool {
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

// Returns the main service type, e.g. `_http._tcp.local.` and any additional subtypes,
// e.g. `_printer._sub._http._tcp.local.`. Responders only.
//
// # See RFC6763 Section 7.1
//
// Format:
// <type>.<domain>.
// _sub.<subtype>.<type>.<domain>.
func (s *Type) responderNames() (types []string) {
	types = append(types, fmt.Sprintf("%s.%s.", s.Name, s.Domain))
	for _, sub := range s.Subtypes {
		types = append(types, fmt.Sprintf("%s._sub.%s.%s.", sub, s.Name, s.Domain))
	}
	return
}

// Returns the query DNS name to use in e.g. a PTR query.
func (s *Type) queryName() (str string) {
	if len(s.Subtypes) > 0 {
		return fmt.Sprintf("%s._sub.%s.%s.", s.Subtypes[0], s.Name, s.Domain)
	} else {
		return fmt.Sprintf("%s.%s.", s.Name, s.Domain)
	}
}

// Returns a complete service path, e.g. `MyDemo\ Service._foobar._tcp.local.`,
// which is composed from service name, its main type and a domain.
func servicePath(s *Type, e *Service) string {
	return fmt.Sprintf("%s.%s.%s.", e.escapeName(), s.Name, s.Domain)
}

// Parse a service path into a service type and its name
func parseServicePath(s string) (ty *Type, name string, err error) {
	parts := dns.SplitDomainName(s)
	var subtypes []string
	// [service, type-identifier, type-proto, domain...]
	if len(parts) < 4 {
		return nil, "", fmt.Errorf("not enough components")
	}
	// The service name may contain dots.
	name = unescapeDns(parts[0])
	typeName := fmt.Sprintf("%s.%s", parts[1], parts[2])
	domain := strings.Join(parts[3:], ".")
	ty = &Type{typeName, subtypes, domain}
	if err := ty.Validate(); err != nil {
		return nil, "", err
	}
	return ty, name, nil
}

// A service provided on the local network. It is reachable at the advertised addresses and port
// number.
type Service struct {
	// A name that identifies a service of a given type, e.g. `Office Printer`
	Name string `json:"name"`

	// A non-zero port number
	Port uint16 `json:"port"`

	// Hostname, e.g. `Bryans-Mac.local`
	Hostname string `json:"hostname"`

	// A set of IP addresses
	Addrs []netip.Addr `json:"addrs"`

	// Optional additional data
	Text []string `json:"text"`

	// Internal expiry data
	ttl    time.Duration
	seenAt time.Time
}

func (i *Service) String() string {
	return fmt.Sprintf("%v (%v)", i.Name, i.Hostname)
}

func (i *Service) Validate() error {
	if i.Hostname == "" {
		return errors.New("no name specified")
	}
	if i.Hostname == "" {
		return errors.New("no hostname specified")
	}
	if i.Port == 0 {
		return errors.New("port is 0")
	}
	return nil
}

func (i *Service) hostname() string {
	return fmt.Sprintf("%v.", i.Hostname)
}

func (i *Service) Equal(o *Service) bool {
	if i.Hostname != o.Hostname || i.Port != o.Port || !slices.Equal(i.Text, o.Text) {
		return false
	}
	// Note we're not sorting ("normalizing") addresses, since the order can indicate preference
	return slices.Equal(i.Addrs, o.Addrs)
}

// RFC 6763 Section 4.3: [...] the <Instance> portion is allowed to contain any characters
// Spaces and backslashes are escaped by "github.com/miekg/dns".
func (s *Service) escapeName() string {
	return strings.ReplaceAll(s.Name, ".", "\\.")
}
