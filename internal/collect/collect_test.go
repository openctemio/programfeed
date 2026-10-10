package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/programfeed/internal/bundle"
	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
	"github.com/openctemio/programfeed/internal/source"
)

type fake struct {
	name string
	res  *source.Result
	err  error
}

func (f fake) Meta() source.Meta {
	return source.Meta{Name: f.name, URL: "https://openctem.io/" + f.name, Terms: "https://openctem.io/terms", Licence: "CC0-1.0"}
}

func (f fake) Collect(context.Context, *fetch.Client) (*source.Result, error) {
	if f.err != nil {
		return nil, f.err
	}
	// Return copies: the collector normalises in place.
	out := *f.res
	out.Programs = append([]model.Program(nil), f.res.Programs...)
	for i := range out.Programs {
		p := &out.Programs[i]
		p.InScope = append([]model.Target(nil), p.InScope...)
	}
	return &out, nil
}

var day0 = time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)

func prog(src, slug string, targets ...string) model.Program {
	p := model.Program{
		ID: src + ":" + slug, Source: src, Platform: "self-hosted", Name: slug, URL: "https://" + slug + ".org/security",
		Type: model.TypeVDP, Status: model.StatusOpen, InScope: []model.Target{}, OutOfScope: []model.Target{},
		Terms:      model.Terms{URL: "https://" + slug + ".org/security"},
		Provenance: model.Provenance{Source: src, SourceURL: "https://openctem.io/" + src, FetchedAt: day0},
	}
	for _, t := range targets {
		typ := model.TargetDomain
		if strings.HasPrefix(t, "*.") {
			typ = model.TargetWildcard
		}
		p.InScope = append(p.InScope, model.Target{Type: typ, Value: t})
	}
	return p
}

func run(t *testing.T, prev *bundle.Snapshot, at time.Time, allowMass bool, srcs ...source.Source) *bundle.Snapshot {
	t.Helper()
	next, err := Build(context.Background(), prev, srcs, nil, Options{Now: at, AllowMassChange: allowMass})
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func kinds(s *bundle.Snapshot) string {
	var out []string
	for _, c := range s.Changes {
		k := c.Program + " " + c.Kind
		if c.Target != nil {
			k += " " + c.Scope + ":" + c.Target.Value
		}
		out = append(out, k)
	}
	return strings.Join(out, "\n")
}

func TestBuildLifecycle(t *testing.T) {
	s1 := run(t, nil, day0, false, fake{name: "d", res: &source.Result{Programs: []model.Program{
		prog("d", "acme", "acme.org", "*.com"),
		prog("d", "beta", "beta.org"),
		prog("d", "acme", "acme.org"), // duplicate id: first wins
	}}})
	if s1.Sequence != 1 || len(s1.Programs) != 2 || kinds(s1) != "d:acme program_added\nd:beta program_added" {
		t.Fatalf("first build:\n%s", kinds(s1))
	}
	acme := s1.Programs["d:acme"]
	if len(acme.InScope) != 1 || len(acme.Rejected) != 1 || !acme.FirstSeen.Equal(day0) {
		t.Fatalf("acme: %+v", acme)
	}

	// Day 1: acme gains a target and loses none, beta disappears.
	day1 := day0.Add(24 * time.Hour)
	s2 := run(t, s1, day1, false, fake{name: "d", res: &source.Result{Programs: []model.Program{
		prog("d", "acme", "acme.org", "*.com", "api.acme.org"),
	}}})
	want := "d:acme target_added in:api.acme.org\nd:beta program_closed"
	if s2.Sequence != 2 || kinds(s2) != want {
		t.Fatalf("day 1:\n%s\nwant\n%s", kinds(s2), want)
	}
	if b := s2.Programs["d:beta"]; b.Status != model.StatusClosed || b.ClosedAt == nil || !b.LastSeen.Equal(day0) {
		t.Errorf("beta: %+v", b)
	}
	if a := s2.Programs["d:acme"]; !a.FirstSeen.Equal(day0) || !a.LastChanged.Equal(day1) || !a.LastSeen.Equal(day1) {
		t.Errorf("acme timestamps: %+v", a)
	}

	// Day 2: nothing changes: no change entries, last_changed stays.
	day2 := day1.Add(24 * time.Hour)
	s3 := run(t, s2, day2, false, fake{name: "d", res: &source.Result{Programs: []model.Program{
		prog("d", "acme", "acme.org", "*.com", "api.acme.org"),
	}}})
	if len(s3.Changes) != 0 || !s3.Programs["d:acme"].LastChanged.Equal(day1) {
		t.Fatalf("day 2:\n%s", kinds(s3))
	}

	// Beta comes back with a different target set; acme loses a target.
	s4 := run(t, s3, day2.Add(time.Hour), false, fake{name: "d", res: &source.Result{Programs: []model.Program{
		prog("d", "acme", "acme.org"),
		prog("d", "beta", "beta.org", "www.beta.org"),
	}}})
	want = "d:acme program_modified\nd:acme target_removed in:api.acme.org\nd:beta program_reopened\nd:beta target_added in:www.beta.org"
	if kinds(s4) != want {
		t.Fatalf("reopen:\n%s\nwant\n%s", kinds(s4), want)
	}

	// A program closed for longer than DropAfter is dropped.
	s5 := run(t, s4, day2.Add(2*time.Hour), false, fake{name: "d", res: &source.Result{Programs: []model.Program{prog("d", "acme", "acme.org")}}})
	s6 := run(t, s5, day2.Add(DropAfter+3*time.Hour), false, fake{name: "d", res: &source.Result{Programs: []model.Program{prog("d", "acme", "acme.org")}}})
	if _, still := s6.Programs["d:beta"]; still || kinds(s6) != "d:beta program_dropped" {
		t.Fatalf("drop:\n%s", kinds(s6))
	}
}

func TestBuildKeepsRecordsOfFailingSources(t *testing.T) {
	s1 := run(t, nil, day0, false,
		fake{name: "a", res: &source.Result{Programs: []model.Program{prog("a", "one", "one.org"), prog("a", "two", "two.org")}}},
		fake{name: "b", res: &source.Result{Programs: []model.Program{prog("b", "three", "three.org")}}})
	day1 := day0.Add(24 * time.Hour)
	// Source a is down, source b reports "two"'s host unknown... and b's
	// program unknown: both keep their records unchanged.
	s2 := run(t, s1, day1, false,
		fake{name: "a", err: errors.New("HTTP 503")},
		fake{name: "b", res: &source.Result{Unknown: []string{"b:three"}}})
	if len(s2.Programs) != 3 || len(s2.Changes) != 0 {
		t.Fatalf("kept %d, changes:\n%s", len(s2.Programs), kinds(s2))
	}
	for _, p := range s2.Programs {
		if p.Status != model.StatusOpen || !p.LastSeen.Equal(day0) {
			t.Errorf("%s: %+v", p.ID, p)
		}
	}
	if src, _ := s2.Source("a"); !src.AsOf.Equal(day0) {
		t.Errorf("a failing source keeps its old as_of: %+v", src)
	}
	// Every source failing fails the build.
	if _, err := Build(context.Background(), s1, []source.Source{fake{name: "a", err: errors.New("down")}}, nil, Options{Now: day1}); err == nil {
		t.Error("a build with no readable source succeeded")
	}
}

func TestMassChangeGuard(t *testing.T) {
	var many []model.Program
	for i := 0; i < 40; i++ {
		many = append(many, prog("d", fmt.Sprintf("p%02d", i), fmt.Sprintf("p%02d.org", i)))
	}
	s1 := run(t, nil, day0, false, fake{name: "d", res: &source.Result{Programs: many}})
	few := &source.Result{Programs: many[:5]}
	other := fake{name: "o", res: &source.Result{Programs: []model.Program{prog("o", "x", "x.org")}}}
	// With another readable source, the guarded source keeps its records.
	s2 := run(t, s1, day0.Add(time.Hour), false, fake{name: "d", res: few}, other)
	if len(s2.Programs) != 41 || s2.Stats().Closed != 0 {
		t.Fatalf("guard did not hold: %+v", s2.Stats())
	}
	// Alone, it fails the build and says why.
	if _, err := Build(context.Background(), s1, []source.Source{fake{name: "d", res: few}}, nil, Options{Now: day0.Add(time.Hour)}); err == nil || !strings.Contains(err.Error(), "allow-mass-change") {
		t.Fatalf("guard alone: %v", err)
	}
	s3 := run(t, s1, day0.Add(time.Hour), true, fake{name: "d", res: few})
	if s3.Stats().Closed != 35 {
		t.Fatalf("override: %+v", s3.Stats())
	}
}

func TestSourceCannotWriteAnotherSourcesPrograms(t *testing.T) {
	evil := prog("a", "victim", "victim.org") // claims source a, served by b
	s := run(t, nil, day0, false,
		fake{name: "a", res: &source.Result{Programs: []model.Program{prog("a", "real", "real.org")}}},
		fake{name: "b", res: &source.Result{Programs: []model.Program{evil, prog("b", "ok", "ok.org")}}})
	if _, ok := s.Programs["a:victim"]; ok || len(s.Programs) != 2 {
		t.Fatalf("programs: %v", s.SortedIDs())
	}
}
