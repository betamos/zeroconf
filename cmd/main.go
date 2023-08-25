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
	browse = flag.Bool("b", false, "Browse for instances")
	name   = flag.String("p", "", "Publish an instance with the given name.")

	serviceStr = flag.String("service", "_zeroconf-go._tcp", "Set the service type to browse or publish.")

	hostname = flag.String("hostname", "", "Override hostname for the instance.")
	port     = flag.Int("port", 42424, "Override the port for the instance.")
	addrs    = flag.String("addrs", "", "Override IP addrs for the instance (comma-separated).")

	network = flag.String("net", "udp", "Change the network to use ipv4 or ipv6 only.")
	maxAge  = flag.Int("max-age", 60, "Set the max age in seconds.")
	text    = flag.String("text", "", "Text values for the instance (comma-separated).")

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

	instance := &zeroconf.Instance{
		Name: *name,
		Port: uint16(*port),
		Text: split(*text),

		Hostname: *hostname,
	}
	for _, addr := range split(*addrs) {
			instance.Addrs = append(instance.Addrs, netip.MustParseAddr(addr))
		}
	service := zeroconf.ParseService(*serviceStr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := zeroconf.New().
		Logger(slog.Default()).
		MaxAge(time.Duration(*maxAge) * time.Second).
		Network(*network)

	var err error
	if *name != "" {
		opts.Publish(service, instance)
		log.Printf("publishing to [%v]: %v\n", service, instance)

	}
	if *browse {
		opts.Browse(service, func(event zeroconf.Event) {
			log.Println(event, event.Text, event.Addrs)
		})
		log.Printf("browsing for [%v]\n", service)
	}
	if !*browse && *name == "" {
		log.Fatalln("either -p <name> (publish) or -b (browse) must be provided (see -help)")
	}

	client, err := opts.Open()
	if err != nil {
		log.Fatalln("failed creating client:", err)
	}
	<-ctx.Done()
	client.Close()

	if err != nil {
		log.Fatalln("failed closing client:", err)
	}
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
