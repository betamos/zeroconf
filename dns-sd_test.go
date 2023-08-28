package zeroconf

import (
	"testing"
)

func TestParseServicePath(t *testing.T) {
	svc, err := parseServicePath("A\\ Device._service._tcp.local.")
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if svc.Name != "A Device" {
		t.Fatalf("service mismatch")
	}
	if svc.Type.Name != "_service._tcp" {
		t.Fatalf("service mismatch")
	}
	if svc.Type.Domain != "local" {
		t.Fatalf("domain mismatch")
	}
}

func TestQueryName(t *testing.T) {
	ty := &Type{
		Name:     "_service._tcp",
		Subtypes: []string{"_printer"},
		Domain:   "local",
	}
	name := queryName(ty)
	expect := "_printer._sub._service._tcp.local."
	if name != expect {
		t.Fatalf("expected %v, got %v", expect, name)
	}
}
