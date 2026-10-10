package source

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// BountyTargetsRepo is the dataset that mirrors the public program
// listings of several bug-bounty platforms as one JSON file per platform.
const BountyTargetsRepo = "arkadiyt/bounty-targets-data"

// BountyTargets reads that dataset. Every record keeps the platform it was
// taken from and that platform's program page; targets are marked
// published_by_platform: the platform listed them for the program, which
// is not permission to test them. Whether a platform's records may be
// published is decided by the publish policy, not here.
type BountyTargets struct {
	Dataset githubDataset
	// Only limits the run to these platforms (nil = every platform the
	// adapter knows). A restricted platform that cannot be published is
	// not even fetched in a signed build.
	Only []string
}

// BountyTargetsPlatforms are the platforms the adapter knows, in order.
func BountyTargetsPlatforms() []string {
	out := make([]string, len(btdPlatforms))
	for i, p := range btdPlatforms {
		out[i] = p.name
	}
	return out
}

// NewBountyTargets returns the adapter for the real dataset.
func NewBountyTargets(only []string) BountyTargets {
	return BountyTargets{Dataset: githubDataset{Repo: BountyTargetsRepo, Ref: "main"}, Only: only}
}

// Meta implements Source.
func (b BountyTargets) Meta() Meta {
	return Meta{
		Name:    "bounty-targets",
		URL:     "https://github.com/" + b.repo(),
		Terms:   "https://github.com/" + b.repo(),
		Licence: "MIT (dataset code); the records stay subject to the terms of the platform they name",
		Attribution: "Program and scope listings aggregated by the " + b.repo() + " project from the public program pages of " +
			"the platforms named in each record.",
	}
}

func (b BountyTargets) repo() string {
	if b.Dataset.Repo != "" {
		return b.Dataset.Repo
	}
	return BountyTargetsRepo
}

type btdPlatform struct {
	platformSpec
	file  string
	parse func(raw json.RawMessage) (*dsProgram, bool)
}

var btdPlatforms = []btdPlatform{
	{platformSpec{"bugcrowd", []string{"bugcrowd.com"}}, "bugcrowd_data.json", parseBugcrowd},
	{platformSpec{"hackerone", []string{"hackerone.com"}}, "hackerone_data.json", parseHackerOne},
	{platformSpec{"intigriti", []string{"intigriti.com"}}, "intigriti_data.json", parseIntigriti},
	{platformSpec{"yeswehack", []string{"yeswehack.com"}}, "yeswehack_data.json", parseYesWeHack},
}

// dsProgram is a program as the platform parsers describe it.
type dsProgram struct {
	key     string // handle, unique within the platform
	name    string
	url     string
	bounty  bool
	paused  bool
	harbour string
	in, out []dsTarget
}

type dsTarget struct {
	kind     string
	value    string
	eligible *bool
	maxSev   string
	notes    string
}

// Collect implements Source. Any platform file that cannot be read fails
// the whole source, so one run never mixes commits or half a dataset.
func (b BountyTargets) Collect(ctx context.Context, c *fetch.Client) (*Result, error) {
	commit, err := b.Dataset.resolve(ctx, c)
	if err != nil {
		return nil, err
	}
	meta := b.Meta()
	res := &Result{}
	for _, plat := range btdPlatforms {
		if !wanted(b.Only, plat.name) {
			continue
		}
		fileURL := b.Dataset.rawURL(commit, "data/"+plat.file)
		resp, err := c.Get(fetch.WithDeadline(ctx, datasetDeadline), fileURL, maxDatasetBytes)
		if err != nil {
			return nil, err
		}
		raw, err := decodeRecords(resp.Body, plat.name)
		if err != nil {
			return nil, err
		}
		var progs []*dsProgram
		keys := make([]string, 0, len(raw))
		for _, r := range raw {
			p, ok := plat.parse(r)
			if !ok || p.key == "" || strings.TrimSpace(p.name) == "" || !plat.onPlatform(p.url) {
				res.Skipped++
				continue
			}
			progs = append(progs, p)
			keys = append(keys, p.key)
		}
		slugs := UniqueSlugs(keys)
		for _, p := range progs {
			res.Programs = append(res.Programs, p.toProgram(meta, plat.name, slugs[p.key], b.repo(), commit, fileURL, resp.FetchedAt))
		}
	}
	sort.Slice(res.Programs, func(i, j int) bool { return res.Programs[i].ID < res.Programs[j].ID })
	return res, nil
}

func (p *dsProgram) toProgram(meta Meta, platform, slug, repo, commit, fileURL string, fetched time.Time) model.Program {
	prog := model.Program{
		ID:             meta.Name + ":" + platform + "-" + slug,
		Source:         meta.Name,
		Platform:       platform,
		Name:           p.name,
		URL:            strings.TrimSpace(p.url),
		Type:           model.TypeVDP,
		Status:         model.StatusOpen,
		ScopePublished: true,
		InScope:        targets(p.in),
		OutOfScope:     targets(p.out),
		Rules: model.Rules{SafeHarbour: harbour(p.harbour), TestingRestrictions: []string{}, RequiredHeaders: []string{},
			Languages: []string{}},
		Terms: model.Terms{URL: strings.TrimSpace(p.url)},
		Provenance: model.Provenance{Source: meta.Name, SourceURL: fileURL, FetchedAt: fetched,
			Dataset: repo, DatasetCommit: commit, OriginalPlatform: platform, OriginalURL: strings.TrimSpace(p.url)},
	}
	if p.bounty {
		prog.Type = model.TypeBounty
	}
	if p.paused {
		prog.Status = model.StatusPaused
	}
	return prog
}

func targets(in []dsTarget) []model.Target {
	out := make([]model.Target, 0, len(in))
	for _, t := range in {
		typ, val := classify(t.kind, t.value)
		out = append(out, model.Target{Type: typ, Value: val, Confidence: model.ConfidencePublishedByPlatform,
			Eligible: t.eligible, MaxSev: strings.ToLower(t.maxSev), Notes: t.notes})
	}
	return out
}

// lastSegment is the last non-empty path segment of a URL.
func lastSegment(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return parts[len(parts)-1]
}

// ---- HackerOne ----

func parseHackerOne(raw json.RawMessage) (*dsProgram, bool) {
	var r struct {
		Handle  string `json:"handle"`
		Name    string `json:"name"`
		URL     string `json:"url"`
		Bounty  bool   `json:"offers_bounties"`
		State   string `json:"submission_state"`
		Targets struct {
			In  []h1Target `json:"in_scope"`
			Out []h1Target `json:"out_of_scope"`
		} `json:"targets"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, false
	}
	p := &dsProgram{key: r.Handle, name: r.Name, url: r.URL, bounty: r.Bounty, paused: r.State != "open"}
	for _, t := range r.Targets.In {
		p.in = append(p.in, t.target())
	}
	for _, t := range r.Targets.Out {
		p.out = append(p.out, t.target())
	}
	return p, true
}

type h1Target struct {
	Identifier  string `json:"asset_identifier"`
	Type        string `json:"asset_type"`
	Eligible    *bool  `json:"eligible_for_bounty"`
	MaxSeverity string `json:"max_severity"`
	Instruction string `json:"instruction"`
}

func (t h1Target) target() dsTarget {
	kind := kindAuto
	switch t.Type {
	case "SOURCE_CODE":
		kind = kindSource
	case "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "TESTFLIGHT", "OTHER_APK", "WINDOWS_APP_STORE_APP_ID":
		kind = kindMobile
	case "HARDWARE", "DOWNLOADABLE_EXECUTABLES", "AI_MODEL", "SMART_CONTRACT":
		kind = kindOpaque
	}
	return dsTarget{kind: kind, value: t.Identifier, eligible: t.Eligible, maxSev: t.MaxSeverity, notes: t.Instruction}
}

// ---- Bugcrowd ----

func parseBugcrowd(raw json.RawMessage) (*dsProgram, bool) {
	var r struct {
		Name       string   `json:"name"`
		URL        string   `json:"url"`
		SafeHarbor string   `json:"safe_harbor"`
		MaxPayout  *float64 `json:"max_payout"`
		Targets    struct {
			In  []bcTarget `json:"in_scope"`
			Out []bcTarget `json:"out_of_scope"`
		} `json:"targets"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, false
	}
	p := &dsProgram{key: lastSegment(r.URL), name: r.Name, url: r.URL, harbour: r.SafeHarbor,
		bounty: r.MaxPayout != nil && *r.MaxPayout > 0}
	for _, t := range r.Targets.In {
		p.in = append(p.in, t.target())
	}
	for _, t := range r.Targets.Out {
		p.out = append(p.out, t.target())
	}
	return p, true
}

type bcTarget struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	Name   string `json:"name"`
}

func (t bcTarget) target() dsTarget {
	kind := kindAuto
	switch t.Type {
	case "ios", "android":
		kind = kindMobile
	case "hardware", "iot":
		kind = kindOpaque
	}
	v := t.Target
	if v == "" {
		v = t.Name
	}
	return dsTarget{kind: kind, value: v}
}

// ---- Intigriti ----

func parseIntigriti(raw json.RawMessage) (*dsProgram, bool) {
	var r struct {
		Company  string `json:"company_handle"`
		Handle   string `json:"handle"`
		Name     string `json:"name"`
		URL      string `json:"url"`
		Status   string `json:"status"`
		Level    string `json:"confidentiality_level"`
		MaxBount *struct {
			Value float64 `json:"value"`
		} `json:"max_bounty"`
		Targets struct {
			In  []intTarget `json:"in_scope"`
			Out []intTarget `json:"out_of_scope"`
		} `json:"targets"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Company == "" || r.Handle == "" || (r.Level != "" && r.Level != "public") {
		return nil, false
	}
	p := &dsProgram{key: r.Company + "-" + r.Handle, name: r.Name, url: r.URL, paused: r.Status != "open",
		bounty: r.MaxBount != nil && r.MaxBount.Value > 0}
	for _, t := range r.Targets.In {
		p.in = append(p.in, t.target())
	}
	for _, t := range r.Targets.Out {
		p.out = append(p.out, t.target())
	}
	return p, true
}

type intTarget struct {
	Type        string `json:"type"`
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

func (t intTarget) target() dsTarget {
	kind := kindAuto
	switch t.Type {
	case "ios", "android":
		kind = kindMobile
	case "device":
		kind = kindOpaque
	}
	out := dsTarget{kind: kind, value: t.Endpoint, notes: t.Description}
	if strings.EqualFold(strings.TrimSpace(t.Impact), "No Bounty") {
		no := false
		out.eligible = &no
	}
	return out
}

// ---- YesWeHack ----

func parseYesWeHack(raw json.RawMessage) (*dsProgram, bool) {
	var r struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Public    *bool    `json:"public"`
		Disabled  bool     `json:"disabled"`
		MaxBounty *float64 `json:"max_bounty"`
		Targets   struct {
			In  []ywhTarget `json:"in_scope"`
			Out []ywhTarget `json:"out_of_scope"`
		} `json:"targets"`
	}
	if json.Unmarshal(raw, &r) != nil || r.ID == "" || (r.Public != nil && !*r.Public) {
		return nil, false
	}
	p := &dsProgram{key: r.ID, name: r.Name, url: "https://yeswehack.com/programs/" + url.PathEscape(r.ID), paused: r.Disabled,
		bounty: r.MaxBounty != nil && *r.MaxBounty > 0}
	for _, t := range r.Targets.In {
		p.in = append(p.in, t.target())
	}
	for _, t := range r.Targets.Out {
		p.out = append(p.out, t.target())
	}
	return p, true
}

type ywhTarget struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

func (t ywhTarget) target() dsTarget {
	kind := kindAuto
	switch {
	case strings.HasPrefix(t.Type, "mobile-application"):
		kind = kindMobile
	case t.Type == "ai-model" || t.Type == "challenge":
		kind = kindOpaque
	}
	return dsTarget{kind: kind, value: t.Target}
}
