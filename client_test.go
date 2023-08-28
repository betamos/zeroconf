package zeroconf

import (
	"context"
	"testing"
	"time"
)

var (
	testService = &Service{
		Name:     "test-name",
		Port:     8888,
		Hostname: "test-hostname",
	}
	testType    = NewType("_test-zeroconf-go._tcp")
	testSubtype = NewType("_test-zeroconf-go._tcp,_fancy")
)

// Check that a published service can be discovered by a browser
func testBasic(t *testing.T, service *Type) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	pub, err := New().Publish(service, testService).Open()
	if err != nil {
		t.Fatalf("failed creating publisher %v", err)
	}
	defer pub.Close()

	var found *Service
	browser, err := New().Browse(service, func(e Event) {
		e.Addrs = nil
		if e.Op == OpAdded {
			found = e.Service
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
		t.Fatalf("service wasn't found")
	}
	if !found.Equal(testService) {
		t.Fatalf("services not equal, expected [%v], got [%v]", testService, found)
	}
}

func TestBasic(t *testing.T) {
	testBasic(t, testType)
}

func TestBasicSubtype(t *testing.T) {
	testBasic(t, testSubtype)
}
