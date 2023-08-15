package zeroconf

import (
	"context"
	"log"
	"testing"
	"time"
)

var (
	mdnsName           = "test--xxxxxxxxxxxx"
	mdnsService        = "_test--xxxx._tcp"
	mdnsSubtype        = "_test--xxxx._tcp,_fancy"
	mdnsDomain         = "local"
	mdnsPort    uint16 = 8888
)

var defaultConf = &Config{Text: []string{"txtv=0", "lo=1", "la=2"}, Domain: mdnsDomain}

func startMDNS(t *testing.T, port uint16, name, service string, conf *Config) {
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
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})
}

func TestParseInstancePath(t *testing.T) {
	s, instance, err := parseInstancePath("A\\ Device._service._tcp.local.")
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if instance != "A Device" {
		t.Fatalf("instance mismatch")
	}
	if s.Type != "_service._tcp" {
		t.Fatalf("service mismatch")
	}
	if s.Domain != "local" {
		t.Fatalf("domain mismatch")
	}
}

func TestQueryName(t *testing.T) {
	s := &ServiceRecord{
		Type:     "_service._tcp",
		Subtypes: []string{"_printer"},
		Domain:   "local",
	}
	name := s.queryName()
	expect := "_printer._sub._service._tcp.local."
	if name != expect {
		t.Fatalf("expected %v, got %v", expect, name)
	}
}
