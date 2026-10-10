package source

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// DotGovFederalURL is CISA's list of US federal .gov domains (CC0-1.0).
const DotGovFederalURL = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv"

const (
	maxSeedBytes        = 8 << 20
	maxSeedDomains      = 20000
	maxSecurityTxtBytes = 32 << 10
)

// Seed is one domain to look for a security.txt on, with the name of the
// organisation that holds it.
type Seed struct {
	Domain string
	Org    string
}

// SecurityTxt reads RFC 9116 security.txt files from a seed list of
// domains. A file with a Contact and a Policy field is a self-hosted
// disclosure program; the domain it was served from is an inferred target
// (security.txt does not publish a scope).
type SecurityTxt struct {
	// SeedCSV is a CSV whose first column is a domain and third column the
	// organisation (the dotgov-data layout); DotGovFederalURL by default.
	SeedCSV string
	// Extra are additional seeds (from the repository's seed file).
	Extra []Seed
	// Workers is the number of domains read at once (16 by default; each
	// host still gets at most one request per MinInterval).
	Workers int
	// Progress, when set, is called after every 100 domains.
	Progress func(done, total int)
	// Scheme is "https" except in tests.
	Scheme string
	// Now is the time used to judge Expires (time.Now by default).
	Now func() time.Time
}

// Meta implements Source.
func (s SecurityTxt) Meta() Meta {
	return Meta{
		Name:        "securitytxt",
		URL:         s.seedURL(),
		Terms:       "https://www.rfc-editor.org/rfc/rfc9116",
		Licence:     "Seed list: CC0-1.0 (cisagov/dotgov-data). security.txt files: published by each domain for automated retrieval (RFC 9116).",
		Attribution: "Domain seed list from CISA's dotgov-data (CC0-1.0); program data from each domain's own security.txt.",
	}
}

func (s SecurityTxt) seedURL() string {
	if s.SeedCSV != "" {
		return s.SeedCSV
	}
	return DotGovFederalURL
}

// Collect implements Source.
func (s SecurityTxt) Collect(ctx context.Context, c *fetch.Client) (*Result, error) {
	resp, err := c.Get(ctx, s.seedURL(), maxSeedBytes)
	if err != nil {
		return nil, fmt.Errorf("seed list: %w", err)
	}
	seeds, err := ParseSeedCSV(resp.Body)
	if err != nil {
		return nil, err
	}
	seeds = append(seeds, s.Extra...)
	byDomain := map[string]Seed{}
	for _, sd := range seeds {
		d, reason := model.NormalizeTarget(model.TargetDomain, sd.Domain)
		if reason != "" || len(d) > 120 {
			continue
		}
		if _, dup := byDomain[d]; !dup {
			byDomain[d] = Seed{Domain: d, Org: sd.Org}
		}
	}
	if len(byDomain) > maxSeedDomains {
		return nil, fmt.Errorf("seed list: %d domains, over the cap of %d", len(byDomain), maxSeedDomains)
	}
	domains := make([]string, 0, len(byDomain))
	for d := range byDomain {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	workers := s.Workers
	if workers <= 0 {
		workers = 16
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	meta := s.Meta()
	res := &Result{}
	var mu sync.Mutex
	done := 0
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				p, known, err := s.one(ctx, c, meta, byDomain[d], now())
				mu.Lock()
				done++
				if s.Progress != nil && done%100 == 0 {
					s.Progress(done, len(domains))
				}
				switch {
				case p != nil:
					res.Programs = append(res.Programs, *p)
				case err != nil && !known:
					res.Unknown = append(res.Unknown, meta.Name+":"+d)
				default:
					res.Skipped++
				}
				mu.Unlock()
			}
		}()
	}
	for _, d := range domains {
		select {
		case jobs <- d:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	sort.Slice(res.Programs, func(i, j int) bool { return res.Programs[i].ID < res.Programs[j].ID })
	sort.Strings(res.Unknown)
	return res, nil
}

// one reads one domain. known reports whether the answer is definite (a
// file, or a definite "no file"); an indefinite failure keeps the
// previous record.
func (s SecurityTxt) one(ctx context.Context, c *fetch.Client, meta Meta, sd Seed, now time.Time) (*model.Program, bool, error) {
	scheme := s.Scheme
	if scheme == "" {
		scheme = "https"
	}
	u := scheme + "://" + sd.Domain + "/.well-known/security.txt"
	resp, err := c.Get(ctx, u, maxSecurityTxtBytes)
	if err != nil {
		var se *fetch.StatusError
		definite := errors.Is(err, fetch.ErrNotFound) || errors.Is(err, fetch.ErrDisallowed) ||
			errors.Is(err, fetch.ErrTooLarge) || (errors.As(err, &se) && se.Code >= 400 && se.Code < 500)
		return nil, definite, err
	}
	f, err := ParseSecurityTxt(resp.Body)
	if err != nil {
		return nil, true, err
	}
	if !ownedBy(f, resp.URL, sd.Domain) {
		return nil, true, errors.New("security.txt is served for another host")
	}
	policy := firstHTTP(f.Policy)
	if policy == "" {
		return nil, true, errors.New("no Policy field")
	}
	sum := sha256.Sum256(resp.Body)
	fetched := resp.FetchedAt
	name := sd.Org
	if name == "" {
		name = sd.Domain
	} else {
		name += " (" + sd.Domain + ")"
	}
	p := &model.Program{
		ID:       meta.Name + ":" + sd.Domain,
		Source:   meta.Name,
		Platform: "self-hosted",
		Name:     name,
		URL:      policy,
		Type:     model.TypeVDP,
		Status:   model.StatusOpen,
		InScope: []model.Target{{Type: model.TargetDomain, Value: sd.Domain, Confidence: model.ConfidenceInferred,
			Notes: "Domain whose security.txt names this policy; not a published scope."}},
		OutOfScope: []model.Target{},
		Rules: model.Rules{SafeHarbour: model.SafeHarbourUnknown, TestingRestrictions: []string{},
			RequiredHeaders: []string{}, Languages: splitList(strings.Join(f.Languages, ","))},
		Terms:      model.Terms{URL: u, SHA256: hex.EncodeToString(sum[:]), FetchedAt: &fetched},
		Provenance: model.Provenance{Source: meta.Name, SourceURL: u, FetchedAt: resp.FetchedAt},
	}
	if !f.Expires.IsZero() && f.Expires.Before(now) {
		p.Status = model.StatusPaused
		p.Rules.Summary = "The security.txt expired on " + f.Expires.UTC().Format("2006-01-02") + "."
	}
	for _, ct := range f.Contact {
		switch {
		case strings.HasPrefix(ct, "mailto:") && p.Contact.Email == "":
			if addr := strings.TrimPrefix(ct, "mailto:"); validEmail(addr) {
				p.Contact.Email = addr
			}
		case strings.HasPrefix(ct, "https://") && p.Contact.URL == "":
			p.Contact.URL = ct
		}
	}
	return p, true, nil
}

// SecurityTxtFile holds the fields of a security.txt the collector uses.
type SecurityTxtFile struct {
	Contact   []string
	Policy    []string
	Canonical []string
	Languages []string
	Expires   time.Time
	CVDPolicy []string // draft-behring-cvd-policy; recorded, not yet parsed
}

// ParseSecurityTxt parses an RFC 9116 file (a cleartext-signed one too; the
// signature is not checked). It refuses HTML and files without a Contact.
func ParseSecurityTxt(body []byte) (*SecurityTxtFile, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("security.txt: not UTF-8")
	}
	text := string(body)
	if l := strings.ToLower(strings.TrimSpace(text)); strings.HasPrefix(l, "<") || strings.Contains(l, "<html") {
		return nil, errors.New("security.txt: HTML, not a security.txt")
	}
	if strings.HasPrefix(strings.TrimSpace(text), "-----BEGIN PGP SIGNED MESSAGE-----") {
		text = stripClearsign(text)
	}
	f := &SecurityTxtFile{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 4096), maxSecurityTxtBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 2048 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "contact":
			f.Contact = appendCapped(f.Contact, v)
		case "policy":
			f.Policy = appendCapped(f.Policy, v)
		case "canonical":
			f.Canonical = appendCapped(f.Canonical, v)
		case "preferred-languages":
			f.Languages = appendCapped(f.Languages, v)
		case "cvd-policy":
			f.CVDPolicy = appendCapped(f.CVDPolicy, v)
		case "expires":
			if t, err := time.Parse(time.RFC3339, v); err == nil && f.Expires.IsZero() {
				f.Expires = t
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("security.txt: %w", err)
	}
	if len(f.Contact) == 0 {
		return nil, errors.New("security.txt: no Contact field")
	}
	return f, nil
}

func appendCapped(l []string, v string) []string {
	if len(l) >= 16 {
		return l
	}
	return append(l, v)
}

func stripClearsign(text string) string {
	_, rest, ok := strings.Cut(text, "\n\n")
	if !ok {
		_, rest, _ = strings.Cut(text, "\r\n\r\n")
	}
	if i := strings.Index(rest, "-----BEGIN PGP SIGNATURE-----"); i >= 0 {
		rest = rest[:i]
	}
	var b strings.Builder
	for _, line := range strings.Split(rest, "\n") {
		b.WriteString(strings.TrimPrefix(line, "- "))
		b.WriteByte('\n')
	}
	return b.String()
}

// ownedBy: the file was served from the seed domain, or one of its
// Canonical URLs is on the seed domain. A file reached through a redirect
// to another organisation's host, with no Canonical naming the seed domain,
// is that other host's file.
func ownedBy(f *SecurityTxtFile, finalURL, domain string) bool {
	if hostIs(finalURL, domain) {
		return true
	}
	for _, c := range f.Canonical {
		if hostIs(c, domain) {
			return true
		}
	}
	return false
}

func hostIs(raw, domain string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), domain)
}

func firstHTTP(l []string) string {
	for _, v := range l {
		if u, err := url.Parse(v); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(v) <= model.MaxURLLen && !strings.ContainsAny(v, " \t") {
			return v
		}
	}
	return ""
}

func validEmail(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, " <>\"") {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-3 && strings.Contains(s[at:], ".")
}

// ParseSeedCSV reads a seed CSV: header row, domain in column 1, the
// organisation in column 3 (and a sub-organisation in column 4, if any).
func ParseSeedCSV(body []byte) ([]Seed, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	var out []Seed
	first := true
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("seed list: %w", err)
		}
		if first {
			first = false
			if len(rec) > 0 && strings.Contains(strings.ToLower(rec[0]), "domain") {
				continue
			}
		}
		if len(rec) == 0 || strings.TrimSpace(rec[0]) == "" {
			continue
		}
		sd := Seed{Domain: strings.TrimSpace(rec[0])}
		if len(rec) > 2 {
			sd.Org = strings.TrimSpace(rec[2])
		}
		if len(rec) > 3 && strings.TrimSpace(rec[3]) != "" {
			sd.Org += " / " + strings.TrimSpace(rec[3])
		}
		out = append(out, sd)
		if len(out) > maxSeedDomains {
			return nil, fmt.Errorf("seed list: over %d domains", maxSeedDomains)
		}
	}
	return out, nil
}

// ParseSeedFile reads the repository seed file: one domain per line,
// optionally followed by whitespace and an organisation name; # comments.
func ParseSeedFile(body []byte) []Seed {
	var out []Seed
	for _, line := range strings.Split(string(body), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, Seed{Domain: fields[0], Org: strings.Join(fields[1:], " ")})
	}
	return out
}
