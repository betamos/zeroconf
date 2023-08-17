package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/betamos/zeroconf/v2"
)

var (
	name    = flag.String("name", "A Regular Instance", "The name for the service.")
	service = flag.String("service", "_zeroconf-go._tcp", "Set the service type of the new service.")
	port    = flag.Int("port", 42424, "Set the port the service is listening to.")

	addrs    = flag.String("addrs", "", "Publish custom IP addrs (comma-separated).")
	hostname = flag.String("hostname", "", "Override hostname for service.")
)

func main() {
	flag.Parse()

	entry := &zeroconf.ServiceEntry{
		Instance: *name,
		Port:     uint16(*port),
		Text:     []string{"txtv=0", "lo=1", "la=2"},

		Hostname: *hostname,
	}
	if *addrs != "" {
		for _, addr := range strings.Split(*addrs, ",") {
			entry.Addrs = append(entry.Addrs, netip.MustParseAddr(addr))
		}
	}

	server, err := zeroconf.Publish(entry, *service, nil)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	log.Printf("published [%v]: %v\n", *service, entry)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err = server.Serve(ctx)
	log.Println("server closed", err)

}
