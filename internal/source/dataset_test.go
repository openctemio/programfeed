package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/programfeed/internal/model"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// datasetServer serves the recorded fixtures the way GitHub does and
// records the paths requested.
func datasetServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	files := map[string]string{
		"/repos/arkadiyt/bounty-targets-data/commits":                                   "commits.json",
		"/arkadiyt/bounty-targets-data/" + testCommit + "/data/hackerone_data.json":     "hackerone_data.json",
		"/arkadiyt/bounty-targets-data/" + testCommit + "/data/bugcrowd_data.json":      "bugcrowd_data.json",
		"/arkadiyt/bounty-targets-data/" + testCommit + "/data/intigriti_data.json":     "intigriti_data.json",
		"/arkadiyt/bounty-targets-data/" + testCommit + "/data/yeswehack_data.json":     "yeswehack_data.json",
		"/repos/projectdiscovery/public-bugbounty-programs/commits":                     "commits.json",
		"/projectdiscovery/public-bugbounty-programs/" + testCommit + "/dist/data.json": "pd-programs.json",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		f, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join("testdata", "datasets", f))
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

func normalized(ps []model.Program) map[string]model.Program {
	out := map[string]model.Program{}
	for _, p := range ps {
		model.Normalize(&p)
		out[p.ID] = p
	}
	return out
}

func TestBountyTargets(t *testing.T) {
	srv, _ := datasetServer(t)
	b := BountyTargets{Dataset: githubDataset{Repo: BountyTargetsRepo, Ref: "main", APIBase: srv.URL, RawBase: srv.URL}}
	res, err := b.Collect(context.Background(), testClient(srv))
	if err != nil {
		t.Fatal(err)
	}
	// h1: acme, quiet (wrong-host and handle-less skipped, plus a non-object); bc: 2; intigriti: umbrella, old; ywh: initrode, closed-one.
	if len(res.Programs) != 8 || res.Skipped != 5 {
		t.Fatalf("%d programs, %d skipped", len(res.Programs), res.Skipped)
	}
	ps := normalized(res.Programs)
	acme := ps["bounty-targets:hackerone-acme"]
	if acme.Platform != "hackerone" || acme.Type != model.TypeBounty || acme.Status != model.StatusOpen || !acme.ScopePublished ||
		acme.URL != "https://hackerone.com/acme" {
		t.Fatalf("acme: %+v", acme)
	}
	pv := acme.Provenance
	if pv.Dataset != BountyTargetsRepo || pv.DatasetCommit != testCommit || pv.OriginalPlatform != "hackerone" ||
		pv.OriginalURL != "https://hackerone.com/acme" || !strings.HasSuffix(pv.SourceURL, "/"+testCommit+"/data/hackerone_data.json") {
		t.Errorf("provenance: %+v", pv)
	}
	got := map[string]string{}
	for _, tg := range acme.InScope {
		if tg.Confidence != model.ConfidencePublishedByPlatform {
			t.Errorf("target %s has confidence %s", tg.Value, tg.Confidence)
		}
		got[tg.Value] = tg.Type
	}
	want := map[string]string{"*.acmecorp.net": "wildcard", "api.acme.io": "domain", "https://app.acme.io/v1": "url",
		"151.101.8.0/24": "cidr", "com.acme.app": "mobile_app", "https://github.com/acme/tool": "source_repo"}
	if len(got) != len(want) {
		t.Errorf("in scope %v", got)
	}
	for v, typ := range want {
		if got[v] != typ {
			t.Errorf("%s: %q, want %q", v, got[v], typ)
		}
	}
	rej := map[string]string{}
	for _, r := range acme.Rejected {
		rej[r.Value] = r.Reason
	}
	if rej["10.0.0.0/8"] == "" || rej["co.uk"] == "" {
		t.Errorf("a private range and a public suffix must be rejected: %v", rej)
	}
	if len(acme.OutOfScope) != 1 || acme.OutOfScope[0].Value != "blog.acme.io" {
		t.Errorf("out of scope %+v", acme.OutOfScope)
	}
	if quiet := ps["bounty-targets:hackerone-quiet"]; quiet.Status != model.StatusPaused || quiet.Type != model.TypeVDP {
		t.Errorf("quiet: %+v", quiet)
	}
	if _, bad := ps["bounty-targets:hackerone-phish"]; bad {
		t.Error("a program page outside the platform host must be skipped")
	}

	gx := ps["bounty-targets:bugcrowd-globex"]
	if gx.Rules.SafeHarbour != model.SafeHarbourFull || gx.Type != model.TypeBounty || gx.URL != "https://bugcrowd.com/engagements/globex" {
		t.Errorf("globex: %+v", gx)
	}
	types := map[string]string{}
	for _, tg := range gx.InScope {
		types[tg.Value] = tg.Type
	}
	if types["Globex iOS"] != "mobile_app" || types["https://www.globex.io/"] != "url" || types["Globex Router X1"] != "other" || types["151.101.1.7"] != "ip" || types["api.globex.io"] != "domain" {
		t.Errorf("globex targets: %v", types)
	}
	if len(gx.Rejected) != 1 || gx.Rejected[0].Value != "10.1.2.3" {
		t.Errorf("documentation address must be rejected: %+v", gx.Rejected)
	}
	if v := ps["bounty-targets:bugcrowd-initech-vdp"]; v.Type != model.TypeVDP || v.Rules.SafeHarbour != model.SafeHarbourUnknown {
		t.Errorf("initech: %+v", v)
	}

	um := ps["bounty-targets:intigriti-umbrella-umbrellaprogram"]
	if um.Type != model.TypeBounty || len(um.InScope) != 5 || len(um.OutOfScope) != 1 {
		t.Fatalf("umbrella: %+v", um)
	}
	for _, tg := range um.InScope {
		if tg.Value == "portal.umbrella.eu" && (tg.Eligible == nil || *tg.Eligible) {
			t.Error("impact No Bounty must mean not eligible")
		}
	}
	if _, bad := ps["bounty-targets:intigriti-hidden-secret"]; bad {
		t.Error("a non-public program must be skipped")
	}
	if ps["bounty-targets:intigriti-old-gone"].Status != model.StatusPaused {
		t.Error("a suspended program is paused")
	}

	in := ps["bounty-targets:yeswehack-initrode"]
	if in.URL != "https://yeswehack.com/programs/initrode" || in.Type != model.TypeBounty {
		t.Errorf("initrode: %+v", in)
	}
	if len(in.Rejected) != 1 || in.Rejected[0].Value != "admin.internal" {
		t.Errorf("an internal name must be rejected: %+v", in.Rejected)
	}
	if ps["bounty-targets:yeswehack-closed-one"].Status != model.StatusPaused {
		t.Error("a disabled program is paused")
	}
	for id, p := range ps {
		if err := p.Validate(); err == nil {
			continue
		} else if p.FirstSeen.IsZero() {
			continue // timestamps are set by the collector
		} else {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestBountyTargetsOnlyDoesNotFetchOtherPlatforms(t *testing.T) {
	srv, seen := datasetServer(t)
	b := BountyTargets{Dataset: githubDataset{Repo: BountyTargetsRepo, Commit: testCommit, APIBase: srv.URL, RawBase: srv.URL}, Only: []string{"yeswehack"}}
	res, err := b.Collect(context.Background(), testClient(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Programs) != 2 {
		t.Errorf("%d programs", len(res.Programs))
	}
	for _, p := range seen() {
		if strings.Contains(p, "hackerone") || strings.Contains(p, "bugcrowd") || strings.Contains(p, "intigriti") {
			t.Errorf("fetched %s although the platform is not wanted", p)
		}
		if strings.Contains(p, "/commits") {
			t.Error("a pinned commit must not be resolved again")
		}
	}
}

func TestBountyTargetsBadInputs(t *testing.T) {
	srv, _ := datasetServer(t)
	c := testClient(srv)
	if _, err := (BountyTargets{Dataset: githubDataset{Repo: BountyTargetsRepo, Commit: "main", APIBase: srv.URL, RawBase: srv.URL}}).Collect(context.Background(), c); err == nil {
		t.Error("a branch name is not a pinned commit")
	}
	// A dataset that changed shape fails the whole source.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits"):
			_, _ = w.Write([]byte(`[{"sha":"` + testCommit + `"}]`))
		case r.URL.Path == "/robots.txt":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(`{"programs": []}`))
		}
	}))
	defer bad.Close()
	if _, err := (BountyTargets{Dataset: githubDataset{Repo: BountyTargetsRepo, APIBase: bad.URL, RawBase: bad.URL}}).Collect(context.Background(), testClient(bad)); err == nil {
		t.Error("an object where an array is expected must fail the source")
	}
	notSHA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"sha":"../../etc"}]`))
	}))
	defer notSHA.Close()
	if _, err := (BountyTargets{Dataset: githubDataset{Repo: BountyTargetsRepo, APIBase: notSHA.URL, RawBase: notSHA.URL}}).Collect(context.Background(), testClient(notSHA)); err == nil {
		t.Error("a commit that is not 40 hex characters must be refused")
	}
}

func TestPDBounty(t *testing.T) {
	srv, _ := datasetServer(t)
	d := PDBounty{Dataset: githubDataset{Repo: PDBountyRepo, Ref: "main", APIBase: srv.URL, RawBase: srv.URL}}
	res, err := d.Collect(context.Background(), testClient(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Programs) != 3 || res.Skipped != 2 {
		t.Fatalf("%d programs, %d skipped", len(res.Programs), res.Skipped)
	}
	ps := normalized(res.Programs)
	acme := ps["pd-bounty:acme"]
	if acme.Platform != "hackerone" || acme.Type != model.TypeBounty || acme.ScopePublished || len(acme.InScope) != 2 {
		t.Fatalf("acme: %+v", acme)
	}
	for _, tg := range acme.InScope {
		if tg.Confidence != model.ConfidenceInferred {
			t.Errorf("a community-curated domain is inferred, got %s", tg.Confidence)
		}
	}
	if acme.Provenance.DatasetCommit != testCommit || acme.Provenance.OriginalPlatform != "hackerone" || acme.Provenance.Dataset != PDBountyRepo {
		t.Errorf("provenance: %+v", acme.Provenance)
	}
	if ps["pd-bounty:4chan"].Platform != "self-hosted" || ps["pd-bounty:hosted-web3"].Platform != "immunefi" {
		t.Error("platform is derived from the program page host")
	}
	only := PDBounty{Dataset: d.Dataset, Only: []string{"self-hosted"}}
	res, err = only.Collect(context.Background(), testClient(srv))
	if err != nil || len(res.Programs) != 1 {
		t.Errorf("only self-hosted: %v %d", err, len(res.Programs))
	}
}
