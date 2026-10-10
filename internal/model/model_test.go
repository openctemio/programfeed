package model

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	ok := []struct{ typ, in, want string }{
		{TargetDomain, "OpenCTEM.ORG.", "openctem.org"},
		{TargetDomain, "api.openctem.io", "api.openctem.io"},
		{TargetDomain, "bücher.de", "xn--bcher-kva.de"},
		{TargetDomain, "foo.example.co.uk", "foo.example.co.uk"},
		{TargetWildcard, "*.OpenCTEM.io", "*.openctem.io"},
		{TargetWildcard, "*.example.co.uk", "*.example.co.uk"},
		{TargetIP, "8.8.8.8", "8.8.8.8"},
		{TargetIP, "::ffff:8.8.4.4", "8.8.4.4"},
		{TargetIP, "2606:4700::1111", "2606:4700::1111"},
		{TargetCIDR, "8.8.8.1/24", "8.8.8.0/24"},
		{TargetCIDR, "203.1.0.0/16", "203.1.0.0/16"},
		{TargetCIDR, "2606:4700::/48", "2606:4700::/48"},
		{TargetURL, "HTTPS://App.OpenCTEM.io/login#x", "https://app.openctem.io/login"},
		{TargetURL, "https://openctem.io:8443", "https://openctem.io:8443/"},
		{TargetMobileApp, "  com.example.app  ", "com.example.app"},
		{TargetSourceRepo, "https://github.com/openctemio/openctem", "https://github.com/openctemio/openctem"},
	}
	for _, c := range ok {
		got, reason := NormalizeTarget(c.typ, c.in)
		if reason != "" || got != c.want {
			t.Errorf("%s %q = %q (%s), want %q", c.typ, c.in, got, reason, c.want)
		}
	}
	bad := []struct{ typ, in string }{
		{TargetDomain, "com"},
		{TargetDomain, "co.uk"},
		{TargetDomain, "github.io"}, // private public suffix
		{TargetDomain, "localhost"},
		{TargetDomain, "printer.local"},
		{TargetDomain, "corp.internal"},
		{TargetDomain, "example.com"}, // documentation
		{TargetDomain, "10.0.0.1"},
		{TargetDomain, "a..b.com"},
		{TargetDomain, "-bad.com"},
		{TargetDomain, "under_score.com"},
		{TargetDomain, "x.123"},
		{TargetDomain, "foo.*.com"},
		{TargetDomain, strings.Repeat("a", 64) + ".com"},
		{TargetDomain, "bad‮.com"},
		{TargetWildcard, "*.com"},
		{TargetWildcard, "*.co.uk"},
		{TargetWildcard, "*.github.io"},
		{TargetWildcard, "*"},
		{TargetWildcard, "*.*.example.org"},
		{TargetWildcard, "example.org"},
		{TargetIP, "10.1.2.3"},
		{TargetIP, "127.0.0.1"},
		{TargetIP, "169.254.169.254"},
		{TargetIP, "100.64.0.1"},
		{TargetIP, "192.0.2.10"},
		{TargetIP, "::1"},
		{TargetIP, "fd00::1"},
		{TargetIP, "2001:db8::1"},
		{TargetIP, "fe80::1%eth0"},
		{TargetIP, "224.0.0.1"},
		{TargetIP, "not-an-ip"},
		{TargetCIDR, "0.0.0.0/0"},
		{TargetCIDR, "8.0.0.0/8"},
		{TargetCIDR, "8.8.0.0/15"},
		{TargetCIDR, "2606::/16"},
		{TargetCIDR, "10.0.0.0/24"},
		{TargetCIDR, "172.16.5.0/24"},
		{TargetCIDR, "::ffff:8.8.8.0/120"},
		{TargetURL, "javascript:alert(1)"},
		{TargetURL, "ftp://openctem.io/"},
		{TargetURL, "https://user:pw@openctem.io/"},
		{TargetURL, "https://127.0.0.1/"},
		{TargetURL, "https://[::1]/"},
		{TargetURL, "https://*.openctem.io/"},
		{TargetURL, "https://com/"},
		{TargetURL, "https://openctem.io:99999/"},
		{TargetOther, ""},
		{TargetOther, "a\x00b"},
		{"subnet", "1.2.3.0/24"},
	}
	for _, c := range bad {
		if got, reason := NormalizeTarget(c.typ, c.in); reason == "" {
			t.Errorf("%s %q accepted as %q", c.typ, c.in, got)
		}
	}
}

func FuzzNormalizeTarget(f *testing.F) {
	for _, s := range []string{"example.org", "*.a.b.co.uk", "8.8.8.0/24", "https://a.io/x?y#z", "::ffff:1.2.3.4", "xn--bcher-kva.de"} {
		f.Add(s)
	}
	types := []string{TargetDomain, TargetWildcard, TargetIP, TargetCIDR, TargetURL, TargetOther}
	f.Fuzz(func(t *testing.T, s string) {
		for _, typ := range types {
			n, reason := NormalizeTarget(typ, s)
			if reason != "" {
				continue
			}
			// Normalising is idempotent, so every accepted target validates.
			if n2, r2 := NormalizeTarget(typ, n); r2 != "" || n2 != n {
				t.Fatalf("%s %q -> %q -> %q (%s)", typ, s, n, n2, r2)
			}
		}
	})
}

func validProgram() Program {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	return Program{
		ID: "disclose:openctem", Source: "disclose", Platform: "self-hosted", Name: "OpenCTEM",
		URL: "https://openctem.io/security", Type: TypeVDP, Status: StatusOpen,
		InScope:    []Target{{Type: TargetWildcard, Value: "*.openctem.io"}, {Type: TargetDomain, Value: "openctem.io"}, {Type: TargetIP, Value: "8.8.8.8"}},
		OutOfScope: []Target{{Type: TargetDomain, Value: "status.openctem.io"}, {Type: TargetDomain, Value: "openctem.io"}},
		Rules:      Rules{TestingRestrictions: []string{"no DoS", "no DoS"}},
		Terms:      Terms{URL: "https://openctem.io/security"},
		Provenance: Provenance{Source: "disclose", SourceURL: "https://example.org/list.json", FetchedAt: now},
		FirstSeen:  now, LastSeen: now, LastChanged: now,
	}
}

func TestNormalizeProgram(t *testing.T) {
	p := validProgram()
	p.InScope = append(p.InScope, Target{Type: TargetWildcard, Value: "*.com"}, Target{Type: TargetCIDR, Value: "10.0.0.0/8"},
		Target{Type: TargetDomain, Value: "OPENCTEM.io"})
	Normalize(&p)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	var in []string
	for _, x := range p.InScope {
		in = append(in, x.Type+":"+x.Value)
		if x.Confidence != ConfidencePublished {
			t.Errorf("confidence %q", x.Confidence)
		}
	}
	// Sorted, deduplicated, and openctem.io dropped because it is also out of scope.
	if got := strings.Join(in, " "); got != "ip:8.8.8.8 wildcard:*.openctem.io" {
		t.Errorf("in scope = %s", got)
	}
	reasons := map[string]string{}
	for _, r := range p.Rejected {
		reasons[r.Value] = r.Reason
	}
	if reasons["*.com"] == "" || reasons["10.0.0.0/8"] == "" || reasons["openctem.io"] != "also listed out of scope" {
		t.Errorf("rejected = %+v", p.Rejected)
	}
	if len(p.Rules.TestingRestrictions) != 1 || p.Rules.SafeHarbour != SafeHarbourUnknown {
		t.Errorf("rules = %+v", p.Rules)
	}
}

func TestProgramValidateRefuses(t *testing.T) {
	cases := map[string]func(p *Program){
		"bad id":              func(p *Program) { p.ID = "Disclose:X" },
		"id of other source":  func(p *Program) { p.ID = "other:x" },
		"control in name":     func(p *Program) { p.Name = "a\x07b" },
		"empty name":          func(p *Program) { p.Name = " " },
		"bad type":            func(p *Program) { p.Type = "paid" },
		"bounty mismatch":     func(p *Program) { p.OffersBounty = true },
		"closed without time": func(p *Program) { p.Status = StatusClosed },
		"javascript url":      func(p *Program) { p.URL = "javascript:alert(1)" },
		"terms hash no time":  func(p *Program) { p.Terms.SHA256 = strings.Repeat("a", 64) },
		"bad email":           func(p *Program) { p.Contact.Email = "x <a@b.c>" },
		"unsorted targets": func(p *Program) {
			p.InScope = []Target{{Type: TargetDomain, Value: "b.org", Confidence: ConfidencePublished}, {Type: TargetDomain, Value: "a.org", Confidence: ConfidencePublished}}
		},
		"unnormalised target": func(p *Program) {
			p.InScope = []Target{{Type: TargetDomain, Value: "A.org", Confidence: ConfidencePublished}}
		},
		"public suffix target": func(p *Program) {
			p.InScope = []Target{{Type: TargetWildcard, Value: "*.com", Confidence: ConfidencePublished}}
		},
		"nil list":      func(p *Program) { p.OutOfScope = nil },
		"first seen":    func(p *Program) { p.FirstSeen = p.LastSeen.Add(time.Hour) },
		"bad harbour":   func(p *Program) { p.Rules.SafeHarbour = "maybe" },
		"no provenance": func(p *Program) { p.Provenance.FetchedAt = time.Time{} },
	}
	for name, mut := range cases {
		p := validProgram()
		Normalize(&p)
		mut(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChangeValidate(t *testing.T) {
	tgt := Target{Type: TargetDomain, Value: "openctem.io", Confidence: ConfidenceInferred}
	good := []Change{
		{Sequence: 1, Program: "disclose:x", Kind: ChangeProgramAdded},
		{Sequence: 1, Program: "disclose:x", Kind: ChangeTargetAdded, Scope: "in", Target: &tgt},
	}
	for _, c := range good {
		if err := c.Validate(); err != nil {
			t.Error(err)
		}
	}
	bad := []Change{
		{Sequence: 0, Program: "disclose:x", Kind: ChangeProgramAdded},
		{Sequence: 1, Program: "disclose:x", Kind: "deleted"},
		{Sequence: 1, Program: "disclose:x", Kind: ChangeTargetAdded},
		{Sequence: 1, Program: "disclose:x", Kind: ChangeProgramAdded, Scope: "in", Target: &tgt},
		{Sequence: 1, Program: "disclose:x", Kind: ChangeTargetAdded, Scope: "in", Target: &Target{Type: TargetWildcard, Value: "*.com", Confidence: ConfidenceInferred}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("bad change %d accepted", i)
		}
	}
}

func TestDatasetProvenance(t *testing.T) {
	ok := Provenance{Dataset: "o/r", DatasetCommit: strings.Repeat("a", 40), OriginalPlatform: "hackerone", OriginalURL: "https://hackerone.com/x"}
	if err := ok.validateDataset(); err != nil {
		t.Fatal(err)
	}
	if err := (Provenance{}).validateDataset(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Provenance){
		"commit":   func(p *Provenance) { p.DatasetCommit = "main" },
		"dataset":  func(p *Provenance) { p.Dataset = "o/r/extra" },
		"platform": func(p *Provenance) { p.OriginalPlatform = "" },
		"url":      func(p *Provenance) { p.OriginalURL = "javascript:alert(1)" },
		"partial":  func(p *Provenance) { *p = Provenance{Dataset: "o/r"} },
	} {
		p := ok
		mut(&p)
		if p.validateDataset() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
