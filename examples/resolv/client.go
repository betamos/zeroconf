package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/betamos/zeroconf/v2"
)

var (
	service  = flag.String("service", "_workstation._tcp", "Set the service category to look for devices.")
	domain   = flag.String("domain", "local", "Set the search domain. For local networks, default is fine.")
	waitTime = flag.Int("wait", 10, "Duration in [s] to run discovery.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		Domain: *domain,
	}

	entries := make(chan zeroconf.Event)
	go func(results <-chan zeroconf.Event) {
		for entry := range results {
			sym := "[-]"
			if entry.Op == zeroconf.OpAdded {
				sym = "[+]"
			}
			log.Println(sym, entry.ServiceInstanceName(), entry.AddrIPv4, entry.AddrIPv6, entry.Port)
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
