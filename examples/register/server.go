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
	name     = flag.String("name", "GoZeroconfGo", "The name for the service.")
	service  = flag.String("service", "_workstation._tcp", "Set the service type of the new service.")
	domain   = flag.String("domain", "local.", "Set the network domain. Default should be fine.")
	port     = flag.Int("port", 42424, "Set the port the service is listening to.")
	ttl      = flag.Int("ttl", 120, "Set the TTL value in seconds.")
	waitTime = flag.Int("wait", 10, "Duration in [s] to publish service for.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		Text:   []string{"txtv=0", "lo=1", "la=2"},
		TTL:    *ttl,
		Domain: *domain,
	}

	server, err := zeroconf.Register(*name, *service, *port, conf)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	log.Println("Publishing service:")
	log.Println("- Name:", *name)
	log.Println("- Type:", *service)
	log.Println("- Domain:", *domain)
	log.Println("- Port:", *port)
	log.Println("- TTL:", *ttl)

	sigCtx, sigCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigCancel()
	ctx, cancel := context.WithTimeout(sigCtx, time.Second*time.Duration(*waitTime))
	defer cancel()

	err = server.Serve(ctx)
	log.Println("Server shut down:", err)

}
