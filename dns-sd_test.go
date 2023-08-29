package zeroconf

import (
	"slices"
	"testing"
)

func TestParseServicePath(t *testing.T) {
	svc, err := parseServicePath("A\\ Device._chat._tcp.local.")
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if svc.Name != "A Device" {
		t.Fatalf("service mismatch")
	}
	if svc.Type.Name != "_chat._tcp" {
		t.Fatalf("service mismatch")
	}
	if svc.Type.Domain != "local" {
		t.Fatalf("domain mismatch")
	}
}

// TODO: Rename to typePath?
func TestQueryName(t *testing.T) {
	ty := &Type{
		Name:     "_chat._tcp",
		Subtypes: []string{"_printer"},
		Domain:   "local",
	}
	name := queryName(ty)
	expect := "_printer._sub._chat._tcp.local."
	if name != expect {
		t.Fatalf("expected %v, got %v", expect, name)
	}
}

func TestParseTypePath(t *testing.T) {
	expect := &Type{
		Name:   "_chat._tcp",
		Domain: "local",
	}
	got, err := parseQueryName("_chat._tcp.local.")
	if err != nil {
		t.Fatalf("failed parsing type: %v", err)
	}
	if !got.Equal(expect) {
		t.Fatalf("expected [%v], got [%v]", expect, got)
	}
	if !slices.Equal(got.Subtypes, expect.Subtypes) {
		t.Fatalf("subtypes not equal")
	}
}

func TestParseTypePathSubtype(t *testing.T) {
	expect := &Type{
		Name:     "_chat._tcp",
		Subtypes: []string{"_emoji"},
		Domain:   "local",
	}
	got, err := parseQueryName("_emoji._sub._chat._tcp.local.")
	if err != nil {
		t.Fatalf("failed parsing type: %v", err)
	}
	if !got.Equal(expect) {
		t.Fatalf("expected [%v], got [%v]", expect, got)
	}
	if !slices.Equal(got.Subtypes, expect.Subtypes) {
		t.Fatalf("subtypes not equal")
	}
}
