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
	mdnsPort    uint16 = 8888
)

func startMDNS(t *testing.T, port uint16, name, service string) {
	entry := &ServiceEntry{
		Instance: name,
		Port:     port,
	}
	server, err := Publish(entry, service, nil)
	if err != nil {
		t.Fatalf("error while registering mdns service: %s", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go server.Serve(ctx)
	t.Cleanup(cancel)
	log.Printf("Published service: %s, type: %s", name, service)
}

func TestQuickShutdown(t *testing.T) {
	entry := &ServiceEntry{
		Instance: mdnsName,
		Port:     mdnsPort,
	}
	server, err := Publish(entry, mdnsService, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
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
	startMDNS(t, mdnsPort, mdnsName, mdnsService)

	entries := make([]Event, 0)
	Browse(ctx, mdnsService, func(e Event) {
		entries = append(entries, e)
	}, nil)
	<-ctx.Done()

	if len(entries) < 1 {
		t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
	}
	result := entries[0]
	if result.Instance != mdnsName {
		t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
	}
	if result.Port != mdnsPort {
		t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
	}
}

func TestNoPublish(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entries := make([]Event, 0)
	Browse(ctx, mdnsService, func(e Event) {
		entries = append(entries, e)
	}, nil)
	<-ctx.Done()

	if len(entries) > 0 {
		t.Fatalf("Expected 0 service entries, but got %d", len(entries))
	}
}

func TestSubtype(t *testing.T) {
	t.Run("browse with subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype)

		entries := make([]Event, 0)
		Browse(ctx, mdnsService, func(e Event) {
			entries = append(entries, e)
		}, nil)
		<-ctx.Done()

		if len(entries) < 1 {
			t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
		}
		result := entries[0]
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

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype)

		entries := make([]Event, 0)
		Browse(ctx, mdnsService, func(e Event) {
			entries = append(entries, e)
		}, nil)
		<-ctx.Done()

		if len(entries) < 1 {
			t.Fatalf("Expected >=1 service entries, but got %d", len(entries))
		}
		result := entries[0]
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
