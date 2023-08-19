package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/betamos/zeroconf/v2"
)

var (
	publish = flag.Bool("p", false, "Publish, instead of browse")
	name    = flag.String("name", "A Regular Instance", "Published instance name.")

	service = flag.String("service", "_zeroconf-go._tcp", "Set the service type to browse or publish.")

	hostname = flag.String("hostname", "", "Override hostname for the instance.")
	port     = flag.Int("port", 42424, "Override the port for the instance.")
	addrs    = flag.String("addrs", "", "Override IP addrs for the instance (comma-separated).")

	maxAge = flag.Int("max-age", 0, "Set the max age in seconds.")

	verbose = flag.Bool("v", false, "Verbose mode, with debug output.")
)

func main() {
	flag.Parse()

	if *verbose {
		var level = new(slog.LevelVar) // Info by default
		level.Set(slog.LevelDebug)
		h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
		slog.SetDefault(slog.New(h))
	} else {
		log.SetFlags(log.Ltime)
	}

	conf := &zeroconf.Config{
		MaxAge: time.Duration(*maxAge) * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	if *publish {
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

		log.Printf("publishing [%v]: %v\n", *service, entry)
		err = zeroconf.Publish(ctx, entry, *service, nil)

	} else {

		log.Printf("browsing for [%v]\n", *service)
		err = zeroconf.Browse(ctx, *service, func(event zeroconf.Event) {
			log.Println(event, event.Addrs)
		}, conf)
	}

	log.Println(err)

}
