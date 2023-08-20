package zeroconf

import (
	"net"
	"time"
)

const writeTimeout = 10 * time.Millisecond

// IPType specifies the IP traffic of a zeroconf conn.
type IPType uint8

// Options for IPType.
const (
	IPv4        IPType = 0x01
	IPv6        IPType = 0x02
	IPv4AndIPv6        = IPv4 | IPv6 // default option
)

type Config struct {
	// Interfaces to use for mDNS, net.Interfaces by default. Interfaces that don't support
	// multicast are filtered out.
	Interfaces func() ([]net.Interface, error)

	// IP protocol(s) for the conn, default = IPv4AndIPv6.
	// Other instances often announce addrs of both types, independent of this value.
	IPType IPType

	// While browsing, artificially shorten the life-time of them if their advertised TTL is higher,
	// which helps detect services that disappear more promptly. Note that this results in more
	// frequent "live-check" queries. Default is 75 min.
	MaxAge time.Duration
}

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

func (c *Config) interfaces() func() ([]net.Interface, error) {
	if c.Interfaces == nil {
		return net.Interfaces
	}
	return c.Interfaces
}
