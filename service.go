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
	Name string `json:"name"`

	// Domain should be `local`
	Domain string `json:"domain"`

	// Service subtypes, e.g. [`_printer`]. A service can be published with multiple subtypes.
	// While browsing, a single subtype can be specified to narrow the query.
	// Avoid subtypes if possible. Some clients don't support them.
	//
	// See RFC 6763 Section 7.1.
	Subtypes []string `json:"subtypes,omitempty"`
}

// Returns a type based on a string on the form `_my-service._tcp` or `_my-service._udp`.
//
// The domain is `local` by default, but can be specified explicitly. Finally, a comma-
// separated list of subtypes can be added at the end.
func NewType(t string) Type {
	typeParts := strings.Split(t, ",")
	ty := Type{
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

// Returns the main type and domain, e.g. `_chat._tcp.local`.
func (t Type) String() string {
	return fmt.Sprintf("%s.%s", t.Name, t.Domain)
}

// Returns true if the types are equal (excluding subtypes)
func (t Type) Equal(o Type) bool {
	return t.Name == o.Name && t.Domain == o.Domain
}

func (t Type) Validate() error {
	if labels, ok := dns.IsDomainName(t.Name); !ok || labels != 2 {
		return fmt.Errorf("invalid type [%s]", t.Name)
	}
	if labels, ok := dns.IsDomainName(t.Domain); !ok || labels < 1 {
		return fmt.Errorf("invalid domain [%s]", t.Domain)
	}
	for _, subtype := range t.Subtypes {
		if labels, ok := dns.IsDomainName(t.Domain); !ok || labels != 1 {
			return fmt.Errorf("invalid subtype [%s]", subtype)
		}
	}
	return nil
}

// A service reachable on the local network.
type Service struct {
	// The service type
	Type Type `json:"type"`

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
func NewService(ty Type, name string, port uint16) *Service {
	osHostname, _ := os.Hostname()
	return &Service{
		Type:     ty,
		Name:     name,
		Port:     port,
		Hostname: ensureSuffix(osHostname, ".local"),
	}
}

// Returns the full service path, e.g. `My Computer._chat._tcp.local`. This can be used
// as a map key.
func (s *Service) String() string {
	return fmt.Sprintf("%v.%v.%v", s.Name, s.Type.Name, s.Type.Domain)
}

func (s *Service) Validate() error {
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

// Returns true if the services have the same identity, meaning they have the same name and type
// (excluding subtypes). This is equivalent to comparing their string representations.
func (s *Service) Equal(o *Service) bool {
	if s == o {
		return true
	}
	return s.Type.Equal(o.Type) && s.Name == o.Name
}

// Returns true if all fields are equal, except subtypes.
func (s *Service) deepEqual(o *Service) bool {
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

// Returns true if this service matches the provided query type (including subtype, if present).
func (s *Service) Matches(q Type) bool {
	if !q.Equal(s.Type) {
		return false // Main types are not equal
	}
	if len(q.Subtypes) == 1 && slices.Index(s.Type.Subtypes, q.Subtypes[0]) == -1 {
		return false // Expected subtype not found
	}
	return true
}
