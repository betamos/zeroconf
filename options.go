package zeroconf

import (
	"errors"
	"log/slog"
	"net"
	"time"
)

type browser struct {
	types []*Type
	*cache
}

// Options for a Client
type Options struct {
	logger *slog.Logger

	browser *browser
	publish *Service

	ifacesFn func() ([]net.Interface, error)
	network  string
	expiry   time.Duration
}

// Returns a new options with default values. Remember to call `Open` at the end to create a client.
func New() *Options {
	return &Options{
		logger:   slog.Default(),
		network:  "udp",
		ifacesFn: net.Interfaces,
	}
}

// Checks that the options are sound.
func (o *Options) Validate() error {
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
				errs = append(errs, errors.New("too many subtypes for browsing"))
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
func (o *Options) Publish(svc *Service) *Options {
	o.publish = svc
	return o
}

// Browse for services of the given type(s). The callback is invoked on changes. Self-published
// services are ignored.
//
// A type may have at most one subtype, in order to narrow the search.
func (o *Options) Browse(cb func(Event), types ...*Type) *Options {
	o.browser = &browser{
		types: types,
		cache: newCache(cb),
	}
	return o
}

// While browsing, override received TTL (normally 120s) with a custom duration. A low value,
// like 30s, can help detect stale services faster, but results in more frequent "live-check"
// queries. Conversely, a higher value can keep services "around" that tend to be a bit
// unresponsive. Services that unannounce themselves are always removed immediately.
func (o *Options) Expiry(age time.Duration) *Options {
	o.expiry = age
	return o
}

// Change the network to use "udp" (default), "udp4" or "udp6". This will affect self-announced
// addresses, but those received from others can still be either type.
func (o *Options) Network(network string) *Options {
	o.network = network
	return o
}

// Attach a custom logger. The default is `slog.Default()`.
func (o *Options) Logger(l *slog.Logger) *Options {
	o.logger = l
	return o
}

// Use custom network interfaces. The default is `net.Interfaces`.
func (o *Options) Interfaces(fn func() ([]net.Interface, error)) *Options {
	o.ifacesFn = fn
	return o
}

// Open a client with the current options. An error is returned if the options are invalid or
// there's an issue opening the socket.
func (o *Options) Open() (*Client, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return newClient(o)
}
