package zeroconf

import (
	"net"
	"time"
)

type Config struct {
	// Interfaces to use for mDNS, by default all multicast-enabled interfaces
	Interfaces []net.Interface

	// IP protocol(s) for both client and server, default = IPv4AndIPv6.
	// Note that service entries from others may still include addresses of either type.
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
