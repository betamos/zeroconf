package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/betamos/zeroconf/v2"
)

var (
	service  = flag.String("service", "_zeroconf-go._tcp", "Set the service category to look for devices.")
	domain   = flag.String("domain", "", "Set the search domain. For local networks, default is fine.")
	waitTime = flag.Int("wait", 10, "Duration in [s] to run discovery.")
	maxAge   = flag.Int("max-age", 0, "Sets the max age in [s] of service records.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		Domain: *domain,
		MaxAge: time.Duration(*maxAge) * time.Second,
	}

	entries := make(chan zeroconf.Event)
	go func(results <-chan zeroconf.Event) {
		for event := range results {
			log.Println(event)
		}
		log.Println("No more entries.")
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(*waitTime))
	defer cancel()
	// Discover all services on the network (e.g. _workstation._tcp)
	err := zeroconf.Browse(ctx, *service, entries, conf)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	<-ctx.Done()
	// Wait some additional time to see debug messages on go routine shutdown.
	time.Sleep(1 * time.Second)
}
