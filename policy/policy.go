// Package policy decides, per original platform, whether records read from
// a source may go into the signed public feed.
//
// The collector may read every source, but only platforms with
// publish=true reach the signed output. A platform that is not listed is
// not published. The rule is applied to the finished snapshot (Filter) and
// to the previous release (PrunePrev), so switching a platform to
// publish=false removes its records from the feed on the next run instead
// of keeping them as "unchanged".
package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/programfeed/internal/bundle"
	"github.com/openctemio/programfeed/internal/model"
)

//go:embed platforms.json
var defaultJSON []byte

// SelfHosted is the platform name of programs that host their own policy.
const SelfHosted = "self-hosted"

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Platform is the publish policy of one original platform.
type Platform struct {
	Publish         bool   `json:"publish"`
	Attribution     string `json:"attribution"`
	TakedownContact string `json:"takedown_contact,omitempty"` // defaults to the policy-wide contact
	Reason          string `json:"reason,omitempty"`
}

// Policy is the whole configuration.
type Policy struct {
	TakedownContact string              `json:"takedown_contact"`
	Platforms       map[string]Platform `json:"platforms"`
	// ExcludedPrograms are program ids removed on request of the program
	// owner (TAKEDOWN.md); they are never published, whatever their platform.
	ExcludedPrograms []string `json:"excluded_programs,omitempty"`
}

// Default returns the policy compiled into the binary.
func Default() *Policy {
	p, err := Parse(defaultJSON)
	if err != nil {
		panic("policy: embedded platforms.json: " + err.Error())
	}
	return p
}

// Parse reads and checks a policy; unknown fields are an error.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if !strings.Contains(p.TakedownContact, "@") {
		return nil, errors.New("takedown_contact is required")
	}
	if len(p.Platforms) == 0 {
		return nil, errors.New("no platforms")
	}
	for _, id := range p.ExcludedPrograms {
		if !strings.Contains(id, ":") {
			return nil, fmt.Errorf("excluded program %q is not a program id", id)
		}
	}
	for name, pl := range p.Platforms {
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("platform name %q", name)
		}
		if pl.Publish && strings.TrimSpace(pl.Attribution) == "" {
			return nil, fmt.Errorf("platform %s: publish=true needs an attribution text", name)
		}
	}
	return &p, nil
}

// Publishable reports whether records of the platform may be published.
// Unlisted platforms are not.
func (p *Policy) Publishable(platform string) bool {
	return p.Platforms[platform].Publish
}

// PublishablePlatforms lists the platforms with publish=true, sorted.
func (p *Policy) PublishablePlatforms() []string {
	var out []string
	for name, pl := range p.Platforms {
		if pl.Publish {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (p *Policy) contact(platform string) string {
	if c := p.Platforms[platform].TakedownContact; c != "" {
		return c
	}
	return p.TakedownContact
}

// ok reports whether a program may be published: the platform it is
// hosted on and, for dataset records, the original platform both must be
// publishable.
func (p *Policy) ok(prog model.Program) bool {
	for _, id := range p.ExcludedPrograms {
		if id == prog.ID {
			return false
		}
	}
	if !p.Publishable(prog.Platform) {
		return false
	}
	op := prog.Provenance.OriginalPlatform
	return op == "" || p.Publishable(op)
}

// PrunePrev returns the previous release without the programs the policy
// does not allow, and the ids it removed. Without this a platform switched
// to publish=false would stay in the feed as an unchanged record.
func (p *Policy) PrunePrev(prev *bundle.Snapshot) (*bundle.Snapshot, []string) {
	if prev == nil {
		return nil, nil
	}
	out := *prev
	out.Programs = make(map[string]model.Program, len(prev.Programs))
	var removed []string
	for id, prog := range prev.Programs {
		if p.ok(prog) {
			out.Programs[id] = prog
		} else {
			removed = append(removed, id)
		}
	}
	sort.Strings(removed)
	return &out, removed
}

// Filter returns the publishable part of a full snapshot: the programs the
// policy allows, the changes that concern them, a program_dropped change
// for every id in removed (publishable earlier, not any more), and the
// source entries recounted, with the attribution of every platform that
// is present and the takedown contact.
func (p *Policy) Filter(full *bundle.Snapshot, removed []string) *bundle.Snapshot {
	out := bundle.NewSnapshot()
	out.Sequence = full.Sequence
	platforms := map[string]map[string]bool{} // source -> platforms present
	count := map[string]int{}
	for id, prog := range full.Programs {
		if !p.ok(prog) {
			continue
		}
		out.Programs[id] = prog
		count[prog.Source]++
		if platforms[prog.Source] == nil {
			platforms[prog.Source] = map[string]bool{}
		}
		platforms[prog.Source][prog.Platform] = true
	}
	dropped := map[string]bool{}
	for _, c := range full.Changes {
		if _, in := out.Programs[c.Program]; in || c.Kind == model.ChangeProgramDropped {
			out.Changes = append(out.Changes, c)
			if c.Kind == model.ChangeProgramDropped {
				dropped[c.Program] = true
			}
		}
	}
	for _, id := range removed {
		if _, still := out.Programs[id]; still || dropped[id] {
			continue
		}
		out.Changes = append(out.Changes, model.Change{Sequence: full.Sequence, Program: id, Kind: model.ChangeProgramDropped})
	}
	sort.SliceStable(out.Changes, func(i, j int) bool { return out.Changes[i].Program < out.Changes[j].Program })
	for _, s := range full.Sources {
		s.Programs = count[s.Name]
		var names []string
		for name := range platforms[s.Name] {
			if name != SelfHosted {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			s.Attribution += " " + strings.TrimSpace(p.Platforms[name].Attribution)
		}
		if len(names) > 0 {
			s.Attribution += " Removal requests: " + p.contact(names[0]) + " (see TAKEDOWN.md)."
		}
		out.Sources = append(out.Sources, s)
	}
	return out
}
