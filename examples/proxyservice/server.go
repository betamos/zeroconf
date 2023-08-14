package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/betamos/zeroconf/v2"
)

var (
	name     = flag.String("name", "A Proxy Instance", "The name for the service.")
	service  = flag.String("service", "_zeroconf-go._tcp", "Set the service type of the new service.")
	domain   = flag.String("domain", "", "Set the network domain. Default should be fine.")
	host     = flag.String("host", "pc1", "Set host name for service.")
	ip       = flag.String("ip", "::1", "Set IP a service should be reachable.")
	port     = flag.Int("port", 42424, "Set the port the service is listening to.")
	waitTime = flag.Int("wait", 10, "Duration in [s] to publish service for.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		Text:   []string{"txtv=0", "lo=1", "la=2"},
		Domain: *domain,
	}

	addrs := []netip.Addr{netip.MustParseAddr(*ip)}
	server, err := zeroconf.RegisterProxy(*name, *service, uint16(*port), *host, addrs, conf)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	log.Println("Publishing proxy service:")
	log.Println("- Name:", *name)
	log.Println("- Type:", *service)
	log.Println("- Domain:", *domain)
	log.Println("- Port:", *port)
	log.Println("- Host:", *host)
	log.Println("- IP:", *ip)

	sigCtx, sigCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigCancel()
	ctx, cancel := context.WithTimeout(sigCtx, time.Second*time.Duration(*waitTime))
	defer cancel()

	err = server.Serve(ctx)
	log.Println("Server shut down:", err)
}
