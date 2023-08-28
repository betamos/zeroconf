package zeroconf

import (
	"testing"
)

func TestParseServicePath(t *testing.T) {
	ty, name, err := parseServicePath("A\\ Device._service._tcp.local.")
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if name != "A Device" {
		t.Fatalf("service mismatch")
	}
	if ty.Name != "_service._tcp" {
		t.Fatalf("service mismatch")
	}
	if ty.Domain != "local" {
		t.Fatalf("domain mismatch")
	}
}

func TestQueryName(t *testing.T) {
	ty := &Type{
		Name:     "_service._tcp",
		Subtypes: []string{"_printer"},
		Domain:   "local",
	}
	name := ty.queryName()
	expect := "_printer._sub._service._tcp.local."
	if name != expect {
		t.Fatalf("expected %v, got %v", expect, name)
	}
}
