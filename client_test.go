package zeroconf

import (
	"context"
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
