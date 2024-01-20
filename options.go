package zeroconf

import (
	"errors"
	"log/slog"
	"net"
	"time"
)

type browser struct {
	types []Type
	*cache
}

// Options for a Client
type options struct {
	logger *slog.Logger

	browser *browser
	publish *Service

	ifacesFn func() ([]net.Interface, error)
	network  string
	expiry   time.Duration
	srcAddrs bool
}

func defaultOpts() *options {
	return &options{
		logger:   slog.Default(),
		network:  "udp",
		ifacesFn: net.Interfaces,
	}
}

// Checks that the options are sound.
func (o *options) validate() error {
	if o.browser == nil && o.publish == nil {
		return errors.New("either a browser or a publisher must be provided")
	}
	var errs []error
	if o.browser != nil {
		if len(o.browser.types) == 0 {
			return errors.New("no browse types were provided")
		}
		for _, ty := range o.browser.types {
			errs = append(errs, ty.Validate())
			if len(ty.Subtypes) > 1 {
				errs = append(errs, errors.New("at most one subtype is allowed for browsing"))
			}
		}
	}
	if o.publish != nil {
		errs = append(errs, o.publish.Validate())
	}
	return errors.Join(errs...)
}

// Publish a service of a given type. Name, port and hostname are required.
// Addrs are determined dynamically based on network interfaces, but can be overriden.
func (c *Client) Publish(svc *Service) *Client {
	c.opts.publish = svc
	return c
}

// Browse for services of the given type(s). The callback is invoked for every event until closed,
// and must not block. Self-published services are ignored.
//
// A type may have at most one subtype, in order to narrow the search.
func (c *Client) Browse(cb func(Event), types ...Type) *Client {
	c.opts.browser = &browser{
		types: types,
		cache: newCache(cb),
	}
	return c
}

// While browsing, override received TTL (normally 120s) with a custom duration. A low value,
// like 30s, can help detect stale services faster, but results in more frequent "live-check"
// queries. Conversely, a higher value can keep services "around" that tend to be a bit
// unresponsive. Services that unannounce themselves are always removed immediately.
func (c *Client) Expiry(age time.Duration) *Client {
	c.opts.expiry = age
	return c
}

// Change the network to use "udp" (default), "udp4" or "udp6". This will affect self-announced
// addresses, but those received from others can still be either type.
// Note that link-local IPv6 addresses don't work without a device-local zone identifier.
// See `SrcAddrs` for a possible workaround.
func (c *Client) Network(network string) *Client {
	c.opts.network = network
	return c
}

// Use a custom logger. The default is `slog.Default()`.
func (c *Client) Logger(l *slog.Logger) *Client {
	c.opts.logger = l
	return c
}

// Use custom network interfaces. The default is `net.Interfaces`.
func (c *Client) Interfaces(fn func() ([]net.Interface, error)) *Client {
	c.opts.ifacesFn = fn
	return c
}

// Use the source addr of the UDP packets instead of the self-reported addrs over mDNS.
// This should be more accurate and also works with link-local ipv6 addresses, but it's a
// little unorthodox and not tested widely. It also prevents proxy use-cases.
func (c *Client) SrcAddrs(enabled bool) *Client {
	c.opts.srcAddrs = enabled
	return c
}
