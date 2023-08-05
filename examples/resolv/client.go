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

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			sym := "[-]"
			if entry.Expiry.After(time.Now()) {
				sym = "[+]"
			}
			log.Println(sym, entry.ServiceInstanceName(), entry.AddrIPv4, entry.AddrIPv6, entry.Port)
		}
		log.Println("No more entries.")
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(*waitTime))
	defer cancel()
	// Discover all services on the network (e.g. _workstation._tcp)
	err := zeroconf.Browse(ctx, *service, *domain, entries, zeroconf.Unannouncements(), zeroconf.SelectIPTraffic(zeroconf.IPv4AndIPv6))
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	<-ctx.Done()
	// Wait some additional time to see debug messages on go routine shutdown.
	time.Sleep(1 * time.Second)
}
