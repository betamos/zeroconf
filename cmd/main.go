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

	"github.com/betamos/zeroconf"
)

var (
	browse = flag.Bool("b", false, "Browse for services")
	name   = flag.String("p", "", "Publish a service with the given name.")

	typeStr = flag.String("type", "_zeroconf-go._tcp", "Service type.")

	hostname = flag.String("hostname", "", "Override hostname for the service.")
	port     = flag.Int("port", 42424, "Override the port for the service.")
	addrs    = flag.String("addrs", "", "Override IP addrs for the service (comma-separated).")

	network = flag.String("net", "udp", "Change the network to use ipv4 or ipv6 only.")
	expiry  = flag.Int("expiry", 0, "Set a custom expiry in seconds.")
	text    = flag.String("text", "", "Text values for the service (comma-separated).")
	reload  = flag.Int("reload", 0, "Reload every n seconds. 0 means never.")
	src     = flag.Bool("src", false, "Use source- instead of self-reported addresses.")

	verbose = flag.Bool("v", false, "Verbose mode, with debug output.")
)

func main() {
	flag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	log.SetFlags(log.Lmicroseconds)

	ty := zeroconf.NewType(*typeStr)
	svc := zeroconf.NewService(ty, *name, uint16(*port))
	svc.Text = split(*text)
	if *hostname != "" {
		svc.Hostname = *hostname
	}
	for _, addr := range split(*addrs) {
		svc.Addrs = append(svc.Addrs, netip.MustParseAddr(addr))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := zeroconf.New().
		Logger(slog.Default()).
		Expiry(time.Duration(*expiry) * time.Second).
		Network(*network).
		SrcAddrs(*src)

	var err error
	if *name != "" {
		opts.Publish(svc)
		log.Printf("publishing [%v]\n", svc)
	}
	if *browse {
		opts.Browse(func(e zeroconf.Event) {
			log.Println(e.Op, e.Name, e.Addrs)
		}, ty)
		log.Printf("browsing for [%v]\n", ty)
	}
	if !*browse && *name == "" {
		log.Fatalln("either -p <name> (publish) and/or -b (browse) must be provided (see -help)")
	}

	client, err := opts.Open()
	if err != nil {
		log.Fatalln("failed creating client:", err)
	}

	// Reload periodically. The "empty ticker" blocks forever
	ticker := new(time.Ticker)
	if *reload > 0 {
		ticker = time.NewTicker(time.Duration(*reload) * time.Second)
	}
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			client.Reload()
		}
	}
	ticker.Stop()

	if err := client.Close(); err != nil {
		log.Fatalln("failed closing client:", err)
	}
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
