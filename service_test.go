package zeroconf

import (
	"context"
	"log"
	"testing"
	"time"
)

var (
	mdnsName    = "test--xxxxxxxxxxxx"
	mdnsService = "_test--xxxx._tcp"
	mdnsSubtype = "_test--xxxx._tcp,_fancy"
	mdnsDomain  = "local."
	mdnsPort    = 8888
)

var defaultConf = &Config{Text: []string{"txtv=0", "lo=1", "la=2"}, Domain: mdnsDomain}

func startMDNS(t *testing.T, port int, name, service string, conf *Config) {
	// 5353 is default mdns port
	server, err := Register(name, service, port, conf)
	if err != nil {
		t.Fatalf("error while registering mdns service: %s", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go server.Serve(ctx)
	t.Cleanup(cancel)
	log.Printf("Published service: %s, type: %s, domain: %s", name, service, conf.Domain)
}

func TestQuickShutdown(t *testing.T) {
	server, err := Register(mdnsName, mdnsService, mdnsPort, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	t0 := time.Now()
	server.Serve(ctx)
	if time.Since(t0) > 500*time.Millisecond {
		t.Fatal("shutdown took longer than 500ms")
	}
}

func TestBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	startMDNS(t, mdnsPort, mdnsName, mdnsService, defaultConf)

	entries := make(chan Event, 100)
	Browse(ctx, mdnsService, entries, defaultConf)
	<-ctx.Done()

	if len(entries) < 1 {
		t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
	}
	result := <-entries
	if result.Domain != mdnsDomain {
		t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
	}
	if result.Service != mdnsService {
		t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
	}
	if result.Instance != mdnsName {
		t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
	}
	if result.Port != mdnsPort {
		t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
	}
}

func TestNoRegister(t *testing.T) {
	// before register, mdns resolve shuold not have any entry
	entries := make(chan Event)
	go func(results <-chan Event) {
		s, ok := <-results
		if ok {
			t.Errorf("Expected empty service entries but got %v", s)
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	Browse(ctx, mdnsService, entries, defaultConf)
	<-ctx.Done()
	cancel()
}

func TestSubtype(t *testing.T) {
	t.Run("browse with subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, defaultConf)

		entries := make(chan Event, 100)
		Browse(ctx, mdnsService, entries, defaultConf)
		<-ctx.Done()

		if len(entries) < 1 {
			t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("browse without subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, defaultConf)

		entries := make(chan Event, 100)
		Browse(ctx, mdnsService, entries, defaultConf)
		<-ctx.Done()

		if len(entries) < 1 {
			t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("ttl", func(t *testing.T) {
		conf := &Config{TTL: 1, Domain: mdnsDomain}
		t.Cleanup(func() {
		})

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, conf)

		entries := make(chan Event, 100)
		Browse(ctx, mdnsService, entries, defaultConf)

		<-ctx.Done()
		if len(entries) < 1 {
			t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
		}
		res := <-entries
		if res.TTL != 1 {
			t.Fatalf("expected TTL=1, got %d", res.TTL)
		}
	})
}
