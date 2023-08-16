package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/betamos/zeroconf/v2"
)

var (
	name    = flag.String("name", "A Regular Instance", "The name for the service.")
	service = flag.String("service", "_zeroconf-go._tcp", "Set the service type of the new service.")
	domain  = flag.String("domain", "", "Set the network domain. Default should be fine.")
	port    = flag.Int("port", 42424, "Set the port the service is listening to.")
)

func main() {
	flag.Parse()

	conf := &zeroconf.Config{
		Text:   []string{"txtv=0", "lo=1", "la=2"},
		Domain: *domain,
	}

	server, err := zeroconf.Register(*name, *service, uint16(*port), conf)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	log.Println("Publishing service:")
	log.Println("- Name:", *name)
	log.Println("- Type:", *service)
	log.Println("- Domain:", *domain)
	log.Println("- Port:", *port)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err = server.Serve(ctx)
	log.Println("Server shut down:", err)

}
