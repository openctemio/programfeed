package source

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// PDBountyRepo is a community-curated list of public bug-bounty and
// disclosure programs with the domains each one covers.
const PDBountyRepo = "projectdiscovery/public-bugbounty-programs"

// PDBounty reads that list. It carries the program page and a plain list of
// domains per program; the domains are curated by the community, not
// published by the program, so they are inferred targets (suggestions). The
// platform is derived from the program page; the publish policy decides
// per platform.
type PDBounty struct {
	Dataset githubDataset
	// Only keeps programs of these platforms (nil = all).
	Only []string
}

// NewPDBounty returns the adapter for the real dataset.
func NewPDBounty(only []string) PDBounty {
	return PDBounty{Dataset: githubDataset{Repo: PDBountyRepo, Ref: "main"}, Only: only}
}

func (d PDBounty) repo() string {
	if d.Dataset.Repo != "" {
		return d.Dataset.Repo
	}
	return PDBountyRepo
}

// Meta implements Source.
func (d PDBounty) Meta() Meta {
	return Meta{
		Name:        "pd-bounty",
		URL:         "https://github.com/" + d.repo(),
		Terms:       "https://github.com/" + d.repo() + "/blob/main/LICENSE.md",
		Licence:     "MIT (list); program pages stay subject to the terms of the platform they name",
		Attribution: "Program list curated by the " + d.repo() + " community project.",
	}
}

const pdFile = "dist/data.json"

// Collect implements Source.
func (d PDBounty) Collect(ctx context.Context, c *fetch.Client) (*Result, error) {
	commit, err := d.Dataset.resolve(ctx, c)
	if err != nil {
		return nil, err
	}
	fileURL := d.Dataset.rawURL(commit, pdFile)
	resp, err := c.Get(fetch.WithDeadline(ctx, datasetDeadline), fileURL, maxDatasetBytes)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Programs []json.RawMessage `json:"programs"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return nil, fmt.Errorf("pd-bounty: %w", err)
	}
	if len(doc.Programs) > maxDatasetRecords {
		return nil, fmt.Errorf("pd-bounty: %d records, over the cap of %d", len(doc.Programs), maxDatasetRecords)
	}
	type rec struct {
		Name    string   `json:"name"`
		URL     string   `json:"url"`
		Bounty  bool     `json:"bounty"`
		Domains []string `json:"domains"`
	}
	res := &Result{}
	var recs []rec
	var names []string
	for _, raw := range doc.Programs {
		var r rec
		if json.Unmarshal(raw, &r) != nil || strings.TrimSpace(r.Name) == "" || !httpURL(r.URL) {
			res.Skipped++
			continue
		}
		recs = append(recs, r)
		names = append(names, r.Name)
	}
	slugs := UniqueSlugs(names)
	meta := d.Meta()
	for _, r := range recs {
		platform := platformOf(r.URL)
		if !wanted(d.Only, platform) {
			continue
		}
		p := model.Program{
			ID: meta.Name + ":" + slugs[r.Name], Source: meta.Name, Platform: platform, Name: r.Name, URL: strings.TrimSpace(r.URL),
			Type: model.TypeVDP, Status: model.StatusOpen, InScope: []model.Target{}, OutOfScope: []model.Target{},
			Rules: model.Rules{SafeHarbour: model.SafeHarbourUnknown, TestingRestrictions: []string{}, RequiredHeaders: []string{},
				Languages: []string{}},
			Terms: model.Terms{URL: strings.TrimSpace(r.URL)},
			Provenance: model.Provenance{Source: meta.Name, SourceURL: fileURL, FetchedAt: resp.FetchedAt, Dataset: d.repo(),
				DatasetCommit: commit, OriginalPlatform: platform, OriginalURL: strings.TrimSpace(r.URL)},
		}
		if r.Bounty {
			p.Type = model.TypeBounty
		}
		for _, dom := range r.Domains {
			typ, val := classify(kindAuto, dom)
			p.InScope = append(p.InScope, model.Target{Type: typ, Value: val, Confidence: model.ConfidenceInferred,
				Notes: "Domain listed for the program by a community-curated list; not published by the program."})
		}
		res.Programs = append(res.Programs, p)
	}
	sort.Slice(res.Programs, func(i, j int) bool { return res.Programs[i].ID < res.Programs[j].ID })
	return res, nil
}
