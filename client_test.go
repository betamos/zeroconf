package zeroconf

import (
	"context"
	"testing"
	"time"
)

var (
	testInstance = &Instance{
		Name:     "test-name",
		Port:     8888,
		Hostname: "test-hostname",
	}
	testService            = ParseService("_test-zeroconf-go._tcp")
	testServiceWithSubtype = ParseService("_test-zeroconf-go._tcp,_fancy")
)

// Check that a published instance can be discovered by a browser
func testBasic(t *testing.T, service *Service) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	pub, err := New().Publish(service, testInstance).Open()
	if err != nil {
		t.Fatalf("failed creating publisher %v", err)
	}
	defer pub.Close()

	var found *Instance
	browser, err := New().Browse(service, func(e Event) {
		e.Addrs = nil
		if e.Op == OpAdded {
			found = e.Instance
			cancel()
		}
	}).Open()
	if err != nil {
		t.Fatalf("failed creating browser %v", err)
	}
	<-ctx.Done()
	err = browser.Close()
	if err != nil {
		t.Fatalf("failed closing browser %v", err)
	}
	if found == nil {
		t.Fatalf("instance wasn't found")
	}
	if !found.Equal(testInstance) {
		t.Fatalf("instances not equal, expected [%v], got [%v]", testInstance, found)
	}
}

func TestBasic(t *testing.T) {
	testBasic(t, testService)
}

func TestBasicSubtype(t *testing.T) {
	testBasic(t, testServiceWithSubtype)
}
