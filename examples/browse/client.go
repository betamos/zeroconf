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
	maxAge  = flag.Int("max-age", 0, "Sets the max age in [s] of service records.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		MaxAge: time.Duration(*maxAge) * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("browsing for [%v]\n", *service)

	// Discover all services on the network (e.g. _workstation._tcp)
	err := zeroconf.Browse(ctx, *service, func(event zeroconf.Event) {
		log.Println(event, event.Addrs)
	}, conf)
	if err != nil {
		log.Println("browse done:", err)
	}
}
