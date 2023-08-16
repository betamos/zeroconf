package zeroconf

import (
	"testing"

	"github.com/miekg/dns"
)

func TestUnescapeDns(t *testing.T) {
	names := []string{
		"example.com.",
		"Bryan’s iPad.local.", // 3 byte unicode char
		"4 byte unicode 𐍈.",
	}
	for _, name := range names {
		msg := make([]byte, 100)
		_, err := dns.PackDomainName(name, msg, 0, nil, false)
		if err != nil {
			t.Fatalf("failed to pack [%v]: %v", name, err)
		}
		domain, _, err := dns.UnpackDomainName(msg, 0)
		if err != nil {
			t.Fatalf("failed to pack [%v]: %v", name, err)
		}
		got := unescapeDns(domain)
		if got != name {
			t.Fatalf("expected [%v], got [%v]", name, got)
		}
	}
}

func TestUnescapeDDD(t *testing.T) {
	got, expected := unescapeDDD(`\226\128\153`), `’`
	if got != expected {
		t.Fatalf("expected [%v], got [%v]", expected, got)
	}
}
