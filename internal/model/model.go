// Package model is the feed's record model and its validation.
//
// The rules are the ones the OpenCTEM importer applies: a bundle with one
// record the importer would refuse is refused whole, so the collector
// refuses to publish it first. Targets are different: a target the scope
// rules refuse (a public suffix, a private range, a huge CIDR …) does not
// fail the bundle; it is moved to the program's rejected list with the
// reason, so subscribers can see what a program claimed and why the feed
// did not pass it on.
package model

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits (the importer applies the same).
const (
	MaxNameLen      = 200
	MaxTextLen      = 4000
	MaxURLLen       = 2048
	MaxValueLen     = 512
	MaxTargets      = 2000 // per list (in scope, out of scope, rejected)
	MaxListItems    = 32   // testing restrictions, required headers, languages
	MaxPrograms     = 100000
	MaxChangeFields = 16
)

// Program types and statuses.
const (
	TypeBounty = "bounty"
	TypeVDP    = "vdp"

	StatusOpen   = "open"
	StatusPaused = "paused"
	StatusClosed = "closed"
)

// Safe-harbour values.
const (
	SafeHarbourFull    = "full"
	SafeHarbourPartial = "partial"
	SafeHarbourNone    = "none"
	SafeHarbourUnknown = "unknown"
)

// Target types.
const (
	TargetDomain     = "domain"
	TargetWildcard   = "wildcard"
	TargetIP         = "ip"
	TargetCIDR       = "cidr"
	TargetURL        = "url"
	TargetMobileApp  = "mobile_app"
	TargetSourceRepo = "source_repo"
	TargetOther      = "other"
)

// Target confidence: published = the program's own structured scope;
// inferred = derived by the collector (for example the host a program's
// security.txt was served from). An inferred target is a suggestion, never
// an authorisation to test.
const (
	ConfidencePublished = "published"
	ConfidenceInferred  = "inferred"
)

var (
	idRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}:[a-z0-9][a-z0-9._-]{0,127}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	severities = map[string]bool{"": true, "none": true, "low": true, "medium": true, "high": true, "critical": true}
	types      = map[string]bool{TypeBounty: true, TypeVDP: true}
	statuses   = map[string]bool{StatusOpen: true, StatusPaused: true, StatusClosed: true}
	harbours   = map[string]bool{SafeHarbourFull: true, SafeHarbourPartial: true, SafeHarbourNone: true, SafeHarbourUnknown: true}
	targetType = map[string]bool{TargetDomain: true, TargetWildcard: true, TargetIP: true, TargetCIDR: true, TargetURL: true,
		TargetMobileApp: true, TargetSourceRepo: true, TargetOther: true}
	confidences = map[string]bool{ConfidencePublished: true, ConfidenceInferred: true}
)

// Program is one public bug-bounty or vulnerability-disclosure program.
type Program struct {
	ID             string     `json:"id"`       // "<source>:<slug>", stable, owned by one source
	Source         string     `json:"source"`   // the adapter that produced it
	Platform       string     `json:"platform"` // where the program is hosted ("self-hosted" or a platform name)
	Name           string     `json:"name"`
	URL            string     `json:"url"` // the program's policy page
	Type           string     `json:"type"`
	Status         string     `json:"status"`
	OffersBounty   bool       `json:"offers_bounty"`
	ScopePublished bool       `json:"scope_published"` // the source carries the program's own structured scope
	InScope        []Target   `json:"in_scope"`
	OutOfScope     []Target   `json:"out_of_scope"`
	Rejected       []Rejected `json:"rejected"`
	Rules          Rules      `json:"rules"`
	Terms          Terms      `json:"terms"`
	Contact        Contact    `json:"contact"`
	Provenance     Provenance `json:"provenance"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	LastChanged    time.Time  `json:"last_changed"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
}

// Target is one scope entry.
type Target struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Confidence string `json:"confidence"`
	Eligible   *bool  `json:"eligible_for_bounty,omitempty"`
	MaxSev     string `json:"max_severity,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// Rejected is a target the scope rules refused, with the reason.
type Rejected struct {
	Scope  string `json:"scope"` // in | out
	Type   string `json:"type"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Rules summarises how a program may be tested.
type Rules struct {
	Summary             string   `json:"summary,omitempty"`
	TestingRestrictions []string `json:"testing_restrictions"`
	RateLimit           string   `json:"rate_limit,omitempty"`
	RequiredHeaders     []string `json:"required_headers"`
	SafeHarbour         string   `json:"safe_harbour"`
	DisclosureDays      int      `json:"disclosure_days,omitempty"`
	Languages           []string `json:"languages"`
}

// Terms names the program's terms and, when the collector read them, the
// SHA-256 of the exact bytes it read.
type Terms struct {
	URL       string     `json:"url"`
	SHA256    string     `json:"sha256,omitempty"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
}

// Contact is the program's reporting channel.
type Contact struct {
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Provenance records where and when a record was read.
type Provenance struct {
	Source    string    `json:"source"`
	SourceURL string    `json:"source_url"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Validate checks a normalised program.
func (p *Program) Validate() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("program %q: %s", p.ID, fmt.Sprintf(format, args...))
	}
	switch {
	case !idRE.MatchString(p.ID):
		return fail("id must be <source>:<slug> in lower case")
	case !strings.HasPrefix(p.ID, p.Source+":"):
		return fail("id is not under its source %q", p.Source)
	case p.Provenance.Source != p.Source:
		return fail("provenance source %q", p.Provenance.Source)
	case !safeText(p.Name, MaxNameLen) || strings.TrimSpace(p.Name) == "":
		return fail("name is empty, too long or has control characters")
	case !safeText(p.Platform, 64) || p.Platform == "":
		return fail("platform")
	case !types[p.Type]:
		return fail("type %q", p.Type)
	case !statuses[p.Status]:
		return fail("status %q", p.Status)
	case (p.Status == StatusClosed) != (p.ClosedAt != nil):
		return fail("closed_at must be set exactly when the status is closed")
	case p.OffersBounty != (p.Type == TypeBounty):
		return fail("offers_bounty must match the type")
	case p.FirstSeen.IsZero() || p.LastSeen.Before(p.FirstSeen) || p.LastChanged.Before(p.FirstSeen):
		return fail("first_seen must not be after last_seen or last_changed")
	case p.Provenance.FetchedAt.IsZero():
		return fail("provenance fetched_at")
	}
	if err := checkURL(p.URL, true); err != nil {
		return fail("url: %v", err)
	}
	if err := checkURL(p.Provenance.SourceURL, true); err != nil {
		return fail("provenance source_url: %v", err)
	}
	if err := checkURL(p.Terms.URL, true); err != nil {
		return fail("terms url: %v", err)
	}
	if p.Terms.SHA256 != "" && !sha256RE.MatchString(p.Terms.SHA256) {
		return fail("terms sha256")
	}
	if (p.Terms.SHA256 == "") != (p.Terms.FetchedAt == nil) {
		return fail("terms sha256 and fetched_at go together")
	}
	if p.Contact.Email != "" {
		if a, err := mail.ParseAddress(p.Contact.Email); err != nil || a.Address != p.Contact.Email || len(p.Contact.Email) > 254 {
			return fail("contact email")
		}
	}
	if p.Contact.URL != "" {
		if err := checkURL(p.Contact.URL, false); err != nil {
			return fail("contact url: %v", err)
		}
	}
	if err := p.Rules.validate(); err != nil {
		return fail("%v", err)
	}
	for _, list := range []struct {
		name string
		ts   []Target
	}{{"in_scope", p.InScope}, {"out_of_scope", p.OutOfScope}} {
		if list.ts == nil {
			return fail("%s must be a list", list.name)
		}
		if len(list.ts) > MaxTargets {
			return fail("%s has more than %d targets", list.name, MaxTargets)
		}
		for i, t := range list.ts {
			if err := t.Validate(); err != nil {
				return fail("%s: %v", list.name, err)
			}
			if i > 0 && !targetLess(list.ts[i-1], t) {
				return fail("%s is not sorted or has duplicates", list.name)
			}
		}
	}
	if p.Rejected == nil || len(p.Rejected) > MaxTargets {
		return fail("rejected must be a list of at most %d", MaxTargets)
	}
	for _, r := range p.Rejected {
		if (r.Scope != "in" && r.Scope != "out") || !safeText(r.Type, 32) || !safeText(r.Value, MaxValueLen) || !safeText(r.Reason, 200) || r.Reason == "" {
			return fail("rejected entry %q", r.Value)
		}
	}
	return nil
}

func (r Rules) validate() error {
	if !safeText(r.Summary, MaxTextLen) || !safeText(r.RateLimit, 200) {
		return errors.New("rules: summary or rate_limit too long or has control characters")
	}
	if !harbours[r.SafeHarbour] {
		return fmt.Errorf("rules: safe_harbour %q", r.SafeHarbour)
	}
	if r.DisclosureDays < 0 || r.DisclosureDays > 3650 {
		return errors.New("rules: disclosure_days")
	}
	for name, l := range map[string][]string{"testing_restrictions": r.TestingRestrictions, "required_headers": r.RequiredHeaders, "languages": r.Languages} {
		if l == nil || len(l) > MaxListItems {
			return fmt.Errorf("rules: %s must be a list of at most %d", name, MaxListItems)
		}
		for _, s := range l {
			if s == "" || !safeText(s, 500) {
				return fmt.Errorf("rules: %s entry", name)
			}
		}
	}
	return nil
}

// Validate checks a normalised target (Normalize produces only valid ones).
func (t Target) Validate() error {
	if !targetType[t.Type] || !confidences[t.Confidence] || !severities[t.MaxSev] || !safeText(t.Notes, 500) {
		return fmt.Errorf("target %q: type, confidence, max_severity or notes", t.Value)
	}
	n, reason := NormalizeTarget(t.Type, t.Value)
	if reason != "" || n != t.Value {
		return fmt.Errorf("target %q is not a normalised %s (%s)", t.Value, t.Type, reason)
	}
	return nil
}

func targetLess(a, b Target) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return a.Value < b.Value
}

// SortTargets orders targets canonically and drops exact duplicates
// (same type and value; the first wins).
func SortTargets(ts []Target) []Target {
	sort.SliceStable(ts, func(i, j int) bool { return targetLess(ts[i], ts[j]) })
	out := ts[:0]
	for i, t := range ts {
		if i > 0 && t.Type == ts[i-1].Type && t.Value == ts[i-1].Value {
			continue
		}
		out = append(out, t)
	}
	return out
}

// safeText: valid UTF-8, at most max bytes, no control characters other
// than newline and tab, no bidi overrides.
func safeText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

// checkURL accepts absolute http(s) URLs without credentials; mailto is
// allowed where links may be mail links.
func checkURL(s string, httpOnly bool) error {
	if s == "" || len(s) > MaxURLLen || !safeText(s, MaxURLLen) || strings.ContainsAny(s, " \n\t") {
		return errors.New("empty, too long or has spaces/control characters")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme == "mailto" && !httpOnly:
		return nil
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("scheme %q", u.Scheme)
	case u.User != nil:
		return errors.New("credentials in URL")
	case u.Host == "":
		return errors.New("no host")
	}
	return nil
}

// CleanText trims a source string, folds whitespace runs and cuts it to max
// bytes on a rune boundary; it returns "" for text with control
// characters.
func CleanText(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if !safeText(s, len(s)) {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Change is one entry of a run's change log.
type Change struct {
	Sequence uint64   `json:"sequence"`
	Program  string   `json:"program"`
	Kind     string   `json:"kind"`
	Scope    string   `json:"scope,omitempty"`  // in | out, for target changes
	Target   *Target  `json:"target,omitempty"` // the target after (before, for removed)
	Fields   []string `json:"fields,omitempty"` // for program_modified / target_modified
}

// Change kinds.
const (
	ChangeProgramAdded    = "program_added"
	ChangeProgramClosed   = "program_closed"
	ChangeProgramReopened = "program_reopened"
	ChangeProgramDropped  = "program_dropped"
	ChangeProgramModified = "program_modified"
	ChangeStatus          = "status_changed"
	ChangeRules           = "rules_changed"
	ChangeTerms           = "terms_changed"
	ChangeTargetAdded     = "target_added"
	ChangeTargetRemoved   = "target_removed"
	ChangeTargetModified  = "target_modified"
)

var changeKinds = map[string]bool{ChangeProgramAdded: true, ChangeProgramClosed: true, ChangeProgramReopened: true,
	ChangeProgramDropped: true, ChangeProgramModified: true, ChangeStatus: true, ChangeRules: true, ChangeTerms: true,
	ChangeTargetAdded: true, ChangeTargetRemoved: true, ChangeTargetModified: true}

// Validate checks a change entry.
func (c *Change) Validate() error {
	if !idRE.MatchString(c.Program) || !changeKinds[c.Kind] || c.Sequence == 0 || len(c.Fields) > MaxChangeFields {
		return fmt.Errorf("change %q %q: program, kind, sequence or fields", c.Program, c.Kind)
	}
	isTarget := strings.HasPrefix(c.Kind, "target_")
	if isTarget != (c.Target != nil) || isTarget != (c.Scope == "in" || c.Scope == "out") || (!isTarget && c.Scope != "") {
		return fmt.Errorf("change %q %q: target and scope go with target changes only", c.Program, c.Kind)
	}
	if c.Target != nil {
		if err := c.Target.Validate(); err != nil {
			return err
		}
	}
	for _, f := range c.Fields {
		if !safeText(f, 64) || f == "" {
			return fmt.Errorf("change %q: field name", c.Program)
		}
	}
	return nil
}
