package zeroconf

import (
	"context"
	"fmt"
	"testing"
	"time"
)

var (
	testType    = NewType("_test-zeroconf-go._tcp")
	testSubtype = NewType("_test-zeroconf-go._tcp,_fancy")
	testService = &Service{
		Type:     testType,
		Name:     "test-name",
		Port:     8888,
		Hostname: "test-hostname1",
	}
	testSubService = &Service{
		Type:     testSubtype,
		Name:     "test-name",
		Port:     8888,
		Hostname: "test-hostname2",
	}
)

// Check that a published service can be discovered by a browser
func testBasic(t *testing.T, svc *Service) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	pub, err := New().Publish(svc).Open()
	if err != nil {
		t.Fatalf("failed creating publisher %v", err)
	}
	defer pub.Close()

	var found *Service
	browser, err := New().
		Browse(func(e Event) {
			e.Addrs = nil
			if e.Op == OpAdded {
				found = e.Service
				cancel()
			}
		}, svc.Type).
		Open()
	if err != nil {
		t.Fatalf("failed creating browser %v", err)
	}
	<-ctx.Done()
	err = browser.Close()
	if err != nil {
		t.Fatalf("failed closing browser %v", err)
	}
	if found == nil {
		t.Fatalf("service wasn't found")
	}
	if !found.Equal(svc) {
		t.Fatalf("services not equal, expected [%v], got [%v]", svc, found)
	}
}

func TestBasic(t *testing.T) {
	testBasic(t, testService)
}

func TestBasicSubtype(t *testing.T) {
	testBasic(t, testSubService)
}

func Example() {
	// Browse for AirPlay devices on the local network
	ty := NewType("_airplay._tcp")
	zc, _ := New().Browse(func(e Event) {
		fmt.Println(e)
	}, ty).Open()

	defer zc.Close()

	// Main app logic
}

func Example_pubsub() {
	// Publish a service and browse for others of the same type
	ty := NewType("_chat._tcp")
	svc := NewService(ty, "bobs-laptop", 12345)
	zc, _ := New().
		Publish(svc).
		Browse(func(e Event) {
			fmt.Println(e)
		}).Open()
	defer zc.Close()

	// Main app logic
}
