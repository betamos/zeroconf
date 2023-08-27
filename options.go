package zeroconf

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

type publisher struct {
	service  *Service
	instance *Instance
}

type browser struct {
	service *Service
	*cache
}

// Options for a Client
type Options struct {
	logger *slog.Logger

	browser   *browser
	publisher *publisher

	maxPeriod time.Duration // Max period to perform periodic tasks - like sending queries
	ifacesFn  func() ([]net.Interface, error)
	network   string
	maxAge    time.Duration
}

// Returns a new options with default values. Remember to call `Open` at the end to create a client.
func New() *Options {
	return &Options{
		logger:    slog.Default(),
		network:   "udp",
		ifacesFn:  net.Interfaces,
		maxPeriod: time.Minute,
		maxAge:    75 * time.Minute,
	}
}

// Checks that the options are sound.
func (o *Options) Validate() error {
	if o.browser == nil && o.publisher == nil {
		return errors.New("either a browser or a publisher must be provided")
	}
	var errs []error
	if o.browser != nil {
		errs = append(errs, o.browser.service.Validate())
		if len(o.browser.service.Subtypes) > 1 {
			errs = append(errs, errors.New("too many subtypes for browsing"))
		}
	}
	if o.publisher != nil {
		errs = append(errs, o.publisher.service.Validate())
		errs = append(errs, o.publisher.instance.Validate())
	}
	return errors.Join(errs...)
}

// Publish an instance of a service. Name and Port are required.
// Addrs and Hostname are determined automatically, but can be overriden.
func (o *Options) Publish(s *Service, i *Instance) *Options {
	if i.Hostname == "" {
		hostname, _ := strings.CutSuffix(defaultHostname, ".local")
		i.Hostname = fmt.Sprintf("%v.%v", hostname, s.Domain)
	}
	o.publisher = &publisher{s, i}
	return o
}

// Browse for instance of a given service type. Optionally, a single subtype may be provided to
// narrow the search. Events are sent to the provided callback.
//
// Any self-published instance is ignored.
func (o *Options) Browse(s *Service, cb func(Event)) *Options {
	o.browser = &browser{
		service: s,
		cache:   newCache(cb),
	}
	return o
}

// While browsing, override received TTL (normally 120s) with a custom duration. This will remove
// stale instances quicker, but results in more frequent queries.
func (o *Options) MaxAge(age time.Duration) *Options {
	o.maxAge = max(5*time.Second, age)
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