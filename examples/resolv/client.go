package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/betamos/zeroconf/v2"
)

var (
	service = flag.String("service", "_zeroconf-go._tcp", "Set the service category to look for devices.")
	domain  = flag.String("domain", "", "Set the search domain. For local networks, default is fine.")
	maxAge  = flag.Int("max-age", 0, "Sets the max age in [s] of service records.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		Domain: *domain,
		MaxAge: time.Duration(*maxAge) * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Discover all services on the network (e.g. _workstation._tcp)
	err := zeroconf.Browse(ctx, *service, func(event zeroconf.Event) {
		log.Println(event, event.Text)
	}, conf)
	if err != nil {
		log.Println("Failed to browse:", err)
	}
}
