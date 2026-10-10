package model

import (
	"sort"
	"strings"
)

// Normalize canonicalises the targets of a program an adapter produced:
// every target is normalised or moved to Rejected with the reason, lists are
// deduplicated and sorted, an in-scope target that is also out of scope is
// dropped from in scope (out of scope wins), and lists are capped. Text
// fields are cleaned. It does not set the timestamps; the collector does.
func Normalize(p *Program) {
	p.Name = CleanText(p.Name, MaxNameLen)
	p.Platform = CleanText(p.Platform, 64)
	p.Rules.Summary = CleanText(p.Rules.Summary, MaxTextLen)
	p.Rules.RateLimit = CleanText(p.Rules.RateLimit, 200)
	p.Rules.TestingRestrictions = cleanList(p.Rules.TestingRestrictions)
	p.Rules.RequiredHeaders = cleanList(p.Rules.RequiredHeaders)
	p.Rules.Languages = cleanList(p.Rules.Languages)
	if p.Rules.SafeHarbour == "" {
		p.Rules.SafeHarbour = SafeHarbourUnknown
	}
	p.OffersBounty = p.Type == TypeBounty
	var rejected []Rejected
	norm := func(scope string, in []Target) []Target {
		out := make([]Target, 0, len(in))
		for _, t := range in {
			v, reason := NormalizeTarget(t.Type, t.Value)
			if reason != "" {
				rejected = append(rejected, Rejected{Scope: scope, Type: CleanText(t.Type, 32), Value: CleanText(t.Value, MaxValueLen), Reason: reason})
				continue
			}
			t.Value = v
			if t.Confidence == "" {
				t.Confidence = ConfidencePublished
			}
			if !severities[t.MaxSev] {
				t.MaxSev = ""
			}
			t.Notes = CleanText(t.Notes, 500)
			out = append(out, t)
		}
		out = SortTargets(out)
		if len(out) > MaxTargets {
			for _, t := range out[MaxTargets:] {
				rejected = append(rejected, Rejected{Scope: scope, Type: t.Type, Value: t.Value, Reason: "over the per-program target cap"})
			}
			out = out[:MaxTargets]
		}
		return out
	}
	p.OutOfScope = norm("out", p.OutOfScope)
	in := norm("in", p.InScope)
	excluded := map[string]bool{}
	for _, t := range p.OutOfScope {
		excluded[t.Type+"\x00"+t.Value] = true
	}
	p.InScope = in[:0]
	for _, t := range in {
		if excluded[t.Type+"\x00"+t.Value] {
			rejected = append(rejected, Rejected{Scope: "in", Type: t.Type, Value: t.Value, Reason: "also listed out of scope"})
			continue
		}
		p.InScope = append(p.InScope, t)
	}
	for i := range rejected {
		if rejected[i].Value == "" {
			rejected[i].Value = "(unprintable)"
		}
		if rejected[i].Type == "" {
			rejected[i].Type = "unknown"
		}
	}
	sort.SliceStable(rejected, func(i, j int) bool {
		a, b := rejected[i], rejected[j]
		return strings.Join([]string{a.Scope, a.Type, a.Value, a.Reason}, "\x00") < strings.Join([]string{b.Scope, b.Type, b.Value, b.Reason}, "\x00")
	})
	if len(rejected) > MaxTargets {
		rejected = rejected[:MaxTargets]
	}
	if rejected == nil {
		rejected = []Rejected{}
	}
	p.Rejected = rejected
}

func cleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = CleanText(s, 500)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == MaxListItems {
			break
		}
	}
	return out
}
