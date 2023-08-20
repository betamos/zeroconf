package zeroconf

import (
	"context"
	"testing"
	"time"
)

var (
	testName                      = "test--xxxxxxxxxxxx"
	testService                   = "_test--xxxx._tcp"
	testServiceWithSubtype        = "_test--xxxx._tcp,_fancy"
	testPort               uint16 = 8888
)

func startMDNS(t *testing.T, port uint16, name, service string) {
	instance := &Instance{
		Name: name,
		Port: port,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go Publish(ctx, instance, service, nil)
	t.Cleanup(cancel)
}

func TestQuickShutdown(t *testing.T) {
	instance := &Instance{
		Name: testName,
		Port: testPort,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	t0 := time.Now()
	Publish(ctx, instance, testService, nil)
	if time.Since(t0) > 500*time.Millisecond {
		t.Fatal("shutdown took longer than 500ms")
	}
}

func TestBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	startMDNS(t, testPort, testName, testService)

	instances := make([]Event, 0)
	Browse(ctx, testService, func(e Event) {
		instances = append(instances, e)
	}, nil)
	<-ctx.Done()

	if len(instances) < 1 {
		t.Fatalf("Expected >=1 service instances, but got %d", len(instances))
	}
	result := instances[0]
	if result.Name != testName {
		t.Fatalf("Expected instance is %s, but got %s", testName, result.Name)
	}
	if result.Port != testPort {
		t.Fatalf("Expected port is %d, but got %d", testPort, result.Port)
	}
}

func TestNoPublish(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	instances := make([]Event, 0)
	Browse(ctx, testService, func(e Event) {
		instances = append(instances, e)
	}, nil)
	<-ctx.Done()

	if len(instances) > 0 {
		t.Fatalf("Expected 0 service instances, but got %d", len(instances))
	}
}

func TestSubtype(t *testing.T) {
	t.Run("browse with subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		startMDNS(t, testPort, testName, testServiceWithSubtype)

		instances := make([]Event, 0)
		Browse(ctx, testService, func(e Event) {
			instances = append(instances, e)
		}, nil)
		<-ctx.Done()

		if len(instances) < 1 {
			t.Fatalf("Expected >=1 service instances, but got %d", len(instances))
		}
		result := instances[0]
		if result.Name != testName {
			t.Fatalf("Expected instance is %s, but got %s", testName, result.Name)
		}
		if result.Port != testPort {
			t.Fatalf("Expected port is %d, but got %d", testPort, result.Port)
		}
	})

	t.Run("browse without subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		startMDNS(t, testPort, testName, testServiceWithSubtype)

		instances := make([]Event, 0)
		Browse(ctx, testService, func(e Event) {
			instances = append(instances, e)
		}, nil)
		<-ctx.Done()

		if len(instances) < 1 {
			t.Fatalf("Expected >=1 service instances, but got %d", len(instances))
		}
		result := instances[0]
		if result.Name != testName {
			t.Fatalf("Expected instance is %s, but got %s", testName, result.Name)
		}
		if result.Port != testPort {
			t.Fatalf("Expected port is %d, but got %d", testPort, result.Port)
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
	s := &Service{
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
