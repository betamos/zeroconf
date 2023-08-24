package zeroconf

import (
	"testing"
)

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
