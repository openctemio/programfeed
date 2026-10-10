package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// DioDBURL is the disclose.io program list (CC0-1.0).
const DioDBURL = "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json"

const (
	maxDioDBBytes   = 32 << 20
	maxDioDBRecords = 50000
)

// DioDB reads the disclose.io program list: a public directory of
// self-hosted and platform-hosted programs with their policy URL, contact,
// bounty and safe-harbour flags. It carries no structured scope; the only
// target it yields is the host of a program's own security.txt, as an
// inferred target.
type DioDB struct {
	URL string // DioDBURL unless a test overrides it
}

// Meta implements Source.
func (d DioDB) Meta() Meta {
	return Meta{
		Name:        "disclose",
		URL:         d.url(),
		Terms:       "https://github.com/disclose/diodb/blob/master/LICENSE",
		Licence:     "CC0-1.0",
		Attribution: "Program directory data from the disclose.io diodb project (CC0-1.0).",
	}
}

func (d DioDB) url() string {
	if d.URL != "" {
		return d.URL
	}
	return DioDBURL
}

type dioRecord struct {
	ProgramName       string          `json:"program_name"`
	PolicyURL         string          `json:"policy_url"`
	PolicyURLStatus   string          `json:"policy_url_status"`
	ContactEmail      string          `json:"contact_email"`
	ContactURL        string          `json:"contact_url"`
	OffersBounty      json.RawMessage `json:"offers_bounty"`
	SafeHarbor        json.RawMessage `json:"safe_harbor"`
	SecurityTxtURL    json.RawMessage `json:"securitytxt_url"`
	PreferredLanguage json.RawMessage `json:"preferred_languages"`
	DisclosureDays    json.RawMessage `json:"disclosure_timeline_days"`
}

// Hosts of platforms that host programs on their own site: a policy URL on
// one of them names the platform, never the program's own domain.
var platformHosts = map[string]string{
	"hackerone.com": "hackerone", "bugcrowd.com": "bugcrowd", "intigriti.com": "intigriti",
	"yeswehack.com": "yeswehack", "federacy.com": "federacy", "openbugbounty.org": "openbugbounty",
	"hackenproof.com": "hackenproof", "immunefi.com": "immunefi", "huntr.com": "huntr", "huntr.dev": "huntr",
	"whitehub.net": "whitehub", "bugbase.ai": "bugbase", "zerocopter.com": "zerocopter", "hackrate.com": "hackrate",
}

// Collect implements Source.
func (d DioDB) Collect(ctx context.Context, c *fetch.Client) (*Result, error) {
	resp, err := c.Get(ctx, d.url(), maxDioDBBytes)
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		return nil, fmt.Errorf("diodb: %w", err)
	}
	if len(raw) > maxDioDBRecords {
		return nil, fmt.Errorf("diodb: %d records, over the cap of %d", len(raw), maxDioDBRecords)
	}
	res := &Result{}
	recs := make([]dioRecord, 0, len(raw))
	names := make([]string, 0, len(raw))
	for _, r := range raw {
		var rec dioRecord
		if json.Unmarshal(r, &rec) != nil || strings.TrimSpace(rec.ProgramName) == "" || !httpURL(rec.PolicyURL) {
			res.Skipped++
			continue
		}
		recs = append(recs, rec)
		names = append(names, rec.ProgramName)
	}
	slugs := UniqueSlugs(names)
	meta := d.Meta()
	for _, rec := range recs {
		p := model.Program{
			ID:         meta.Name + ":" + slugs[rec.ProgramName],
			Source:     meta.Name,
			Platform:   platformOf(rec.PolicyURL),
			Name:       rec.ProgramName,
			URL:        strings.TrimSpace(rec.PolicyURL),
			Type:       model.TypeVDP,
			Status:     model.StatusOpen,
			InScope:    []model.Target{},
			OutOfScope: []model.Target{},
			Rules: model.Rules{
				SafeHarbour:         harbour(str(rec.SafeHarbor)),
				TestingRestrictions: []string{},
				RequiredHeaders:     []string{},
				Languages:           splitList(str(rec.PreferredLanguage)),
			},
			Terms:      model.Terms{URL: strings.TrimSpace(rec.PolicyURL)},
			Provenance: model.Provenance{Source: meta.Name, SourceURL: meta.URL, FetchedAt: resp.FetchedAt},
		}
		switch strings.ToLower(str(rec.OffersBounty)) {
		case "yes", "true", "partial":
			p.Type = model.TypeBounty
		}
		if strings.EqualFold(rec.PolicyURLStatus, "dead") {
			p.Status = model.StatusPaused
			p.Rules.Summary = "The policy URL did not answer when the directory last checked it."
		}
		if n, err := strconv.Atoi(str(rec.DisclosureDays)); err == nil && n > 0 && n <= 3650 {
			p.Rules.DisclosureDays = n
		}
		if a, err := mail.ParseAddress(strings.TrimSpace(rec.ContactEmail)); err == nil && len(a.Address) <= 254 {
			p.Contact.Email = a.Address
		}
		if u := strings.TrimSpace(rec.ContactURL); httpURL(u) || strings.HasPrefix(u, "mailto:") {
			p.Contact.URL = u
		}
		if host := securityTxtHost(str(rec.SecurityTxtURL)); host != "" {
			p.InScope = append(p.InScope, model.Target{Type: model.TargetDomain, Value: host, Confidence: model.ConfidenceInferred,
				Notes: "Host that serves the program's security.txt; not a published scope."})
		}
		res.Programs = append(res.Programs, p)
	}
	sort.Slice(res.Programs, func(i, j int) bool { return res.Programs[i].ID < res.Programs[j].ID })
	return res, nil
}

// str reads a JSON value that the directory stores as a string, a bool, a
// number or null.
func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return strconv.FormatBool(b)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func httpURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

func hostOf(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

func platformOf(policyURL string) string {
	h := hostOf(policyURL)
	for host, name := range platformHosts {
		if h == host || strings.HasSuffix(h, "."+host) {
			return name
		}
	}
	return "self-hosted"
}

// securityTxtHost returns the host of a first-party security.txt URL, or
// "" when the URL is not one (wrong path, or hosted on a platform).
func securityTxtHost(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Port() != "" {
		return ""
	}
	if u.Path != "/.well-known/security.txt" && u.Path != "/security.txt" {
		return ""
	}
	if platformOf(s) != "self-hosted" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func harbour(s string) string {
	switch strings.ToLower(s) {
	case "full", "yes":
		return model.SafeHarbourFull
	case "partial":
		return model.SafeHarbourPartial
	case "none", "no":
		return model.SafeHarbourNone
	}
	return model.SafeHarbourUnknown
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
