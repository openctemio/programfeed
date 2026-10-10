package policy

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/programfeed/internal/bundle"
	"github.com/openctemio/programfeed/internal/collect"
	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
	"github.com/openctemio/programfeed/internal/source"
)

var day = time.Date(2026, 10, 10, 2, 0, 0, 0, time.UTC)

type fake struct {
	name  string
	progs []model.Program
}

func (f fake) Meta() source.Meta {
	return source.Meta{Name: f.name, URL: "https://openctem.io/" + f.name, Terms: "https://openctem.io/terms", Licence: "test",
		Attribution: "Test data."}
}

func (f fake) Collect(context.Context, *fetch.Client) (*source.Result, error) {
	out := &source.Result{}
	for _, p := range f.progs {
		p.InScope = append([]model.Target(nil), p.InScope...)
		out.Programs = append(out.Programs, p)
	}
	return out, nil
}

// prog builds a dataset record of the platform; hosted names the platform
// recorded in Platform (differs from the original platform only in the
// "mislabelled" case).
func prog(src, platform, slug string) model.Program {
	u := "https://" + platform + ".example.net/" + slug
	p := model.Program{
		ID: src + ":" + slug, Source: src, Platform: platform, Name: "Program " + slug, URL: u, Type: model.TypeBounty,
		Status: model.StatusOpen, ScopePublished: true,
		InScope:    []model.Target{{Type: model.TargetDomain, Value: slug + ".restricted-secret-corp.net", Confidence: model.ConfidencePublishedByPlatform}},
		OutOfScope: []model.Target{}, Terms: model.Terms{URL: u},
		Provenance: model.Provenance{Source: src, SourceURL: "https://openctem.io/" + src, FetchedAt: day,
			Dataset: "o/r", DatasetCommit: strings.Repeat("a", 40), OriginalPlatform: platform, OriginalURL: u},
	}
	return p
}

func build(t *testing.T, pol *Policy, prev *bundle.Snapshot, srcs ...source.Source) (dir string, next *bundle.Snapshot) {
	t.Helper()
	var removed []string
	prev, removed = pol.PrunePrev(prev)
	full, err := collect.Build(context.Background(), prev, srcs, nil, collect.Options{Now: day})
	if err != nil {
		t.Fatal(err)
	}
	next = pol.Filter(full, removed)
	dir = t.TempDir()
	if _, _, _, err := bundle.Write(dir, prev, next, bundle.WriteOptions{Now: day}); err != nil {
		t.Fatal(err)
	}
	return dir, next
}

// output returns everything the signed output would contain: every
// record file, uncompressed, plus the manifests.
func output(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(e.Name(), ".gz") {
			zr, err := gzip.NewReader(strings.NewReader(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			if b, err = io.ReadAll(zr); err != nil {
				t.Fatal(err)
			}
		}
		sb.Write(b)
	}
	return sb.String()
}

func TestDefaultPolicy(t *testing.T) {
	p := Default()
	if got := p.PublishablePlatforms(); len(got) != 1 || got[0] != SelfHosted {
		t.Fatalf("only self-hosted programs may be published by default, got %v", got)
	}
	for _, name := range []string{"hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "hackenproof"} {
		if pl, ok := p.Platforms[name]; !ok || pl.Publish || pl.Reason == "" {
			t.Errorf("%s must be listed with publish=false and a reason: %+v", name, pl)
		}
	}
	if p.Publishable("a-platform-nobody-listed") {
		t.Error("an unlisted platform must not be published")
	}
	if p.TakedownContact != "security@openctem.io" {
		t.Errorf("takedown contact %q", p.TakedownContact)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, doc := range map[string]string{
		"no attribution": `{"takedown_contact":"a@b.io","platforms":{"x":{"publish":true}}}`,
		"no contact":     `{"platforms":{"x":{"publish":false}}}`,
		"unknown field":  `{"takedown_contact":"a@b.io","platforms":{"x":{"publish":false,"publsh":true}}}`,
		"bad name":       `{"takedown_contact":"a@b.io","platforms":{"X Y":{"publish":false}}}`,
		"no platforms":   `{"takedown_contact":"a@b.io","platforms":{}}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Restricted platforms are read (the collector sees them) but never reach
// the signed output: not in the records, the change log, the manifests or
// the source counts.
func TestRestrictedPlatformsNeverReachSignedOutput(t *testing.T) {
	pol := Default()
	var progs []model.Program
	for name, pl := range pol.Platforms {
		if !pl.Publish {
			progs = append(progs, prog("bounty-targets", name, name+"-prog"))
		}
	}
	// A record whose Platform field says self-hosted but whose original
	// platform is restricted must not slip through.
	sneaky := prog("bounty-targets", "hackerone", "sneaky")
	sneaky.Platform = "self-hosted"
	progs = append(progs, sneaky)
	progs = append(progs, prog("bounty-targets", "self-hosted", "own-policy"))
	progs[len(progs)-1].InScope = []model.Target{{Type: model.TargetDomain, Value: "own.openctem.io", Confidence: model.ConfidenceInferred}}
	progs[len(progs)-1].Provenance = model.Provenance{Source: "bounty-targets", SourceURL: "https://openctem.io/bounty-targets", FetchedAt: day}

	dir, next := build(t, pol, nil, fake{name: "bounty-targets", progs: progs})
	if len(next.Programs) != 1 || next.Programs["bounty-targets:own-policy"].ID == "" {
		t.Fatalf("published %v", next.SortedIDs())
	}
	out := output(t, dir)
	if strings.Contains(out, "restricted-secret-corp") {
		t.Error("a target of a restricted platform reached the output")
	}
	for name, pl := range pol.Platforms {
		if !pl.Publish && (strings.Contains(out, name+"-prog") || strings.Contains(out, "\"original_platform\":\""+name+"\"")) {
			t.Errorf("records of %s reached the output", name)
		}
	}
	if strings.Contains(out, "sneaky") {
		t.Error("a record with a restricted original platform reached the output")
	}
	if got := next.Sources[0].Programs; got != 1 {
		t.Errorf("source count %d, want 1", got)
	}
	for _, c := range next.Changes {
		if c.Program != "bounty-targets:own-policy" {
			t.Errorf("change of a restricted program: %+v", c)
		}
	}
}

func TestPublishedPlatformCarriesAttributionAndTakedown(t *testing.T) {
	pol, err := Parse([]byte(`{"takedown_contact":"security@openctem.io","platforms":{
		"self-hosted":{"publish":true,"attribution":"Own pages."},
		"goodco":{"publish":true,"attribution":"Data from GoodCo, used with permission."}}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, next := build(t, pol, nil, fake{name: "bounty-targets", progs: []model.Program{prog("bounty-targets", "goodco", "g1")}})
	if len(next.Programs) != 1 {
		t.Fatal("a publishable platform must be published")
	}
	a := next.Sources[0].Attribution
	if !strings.Contains(a, "GoodCo, used with permission") || !strings.Contains(a, "security@openctem.io") {
		t.Errorf("attribution %q", a)
	}
}

// Switching a platform to publish=false removes its programs from the
// next release with a program_dropped change; they do not linger as
// unchanged records.
func TestSwitchingPlatformOffDropsItsPrograms(t *testing.T) {
	on, _ := Parse([]byte(`{"takedown_contact":"security@openctem.io","platforms":{
		"self-hosted":{"publish":true,"attribution":"Own pages."},
		"goodco":{"publish":true,"attribution":"GoodCo."}}}`))
	off, _ := Parse([]byte(`{"takedown_contact":"security@openctem.io","platforms":{
		"self-hosted":{"publish":true,"attribution":"Own pages."},
		"goodco":{"publish":false}}}`))
	src := fake{name: "bounty-targets", progs: []model.Program{prog("bounty-targets", "goodco", "g1"), prog("bounty-targets", "goodco", "g2")}}
	_, first := build(t, on, nil, src)
	if len(first.Programs) != 2 {
		t.Fatal("setup")
	}
	dir, second := build(t, off, first, src)
	if len(second.Programs) != 0 {
		t.Fatalf("still published: %v", second.SortedIDs())
	}
	dropped := 0
	for _, c := range second.Changes {
		if c.Kind == model.ChangeProgramDropped {
			dropped++
		}
	}
	if dropped != 2 {
		t.Errorf("%d program_dropped changes, want 2", dropped)
	}
	if strings.Contains(output(t, dir), "restricted-secret-corp") {
		t.Error("a switched-off platform still has records in the output")
	}
}

func TestSignRefusesLocalOnlyBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snapshot.manifest.json"), []byte(`{"collector":{"local_only":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Sign(dir, nil, nil, "", day); err == nil || !strings.Contains(err.Error(), "local-only") {
		t.Errorf("signing a local-only bundle: %v", err)
	}
}

func TestExcludedProgramIsNeverPublished(t *testing.T) {
	pol, err := Parse([]byte(`{"takedown_contact":"security@openctem.io","excluded_programs":["disclose:gone"],"platforms":{
		"self-hosted":{"publish":true,"attribution":"Own pages."}}}`))
	if err != nil {
		t.Fatal(err)
	}
	keep, gone := prog("disclose", "self-hosted", "kept"), prog("disclose", "self-hosted", "gone")
	_, next := build(t, pol, nil, fake{name: "disclose", progs: []model.Program{keep, gone}})
	if len(next.Programs) != 1 || next.Programs["disclose:kept"].ID == "" {
		t.Fatalf("published %v", next.SortedIDs())
	}
	if _, err := Parse([]byte(`{"takedown_contact":"a@b.io","excluded_programs":["nocolon"],"platforms":{"x":{"publish":false}}}`)); err == nil {
		t.Error("an excluded entry that is not a program id was accepted")
	}
}
