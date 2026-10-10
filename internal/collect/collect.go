// Package collect builds the next snapshot: the previous one merged with
// what each source says now, and the change log between them.
package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/programfeed/internal/bundle"
	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
	"github.com/openctemio/programfeed/internal/source"
)

// DropAfter is how long a closed program stays in the feed before it is
// dropped (so subscribers see the closure first).
const DropAfter = 180 * 24 * time.Hour

// Mass-change guard: a source that suddenly reports fewer than half of the
// programs it had (and had at least massMinimum) is treated as broken for
// this run, and its previous records are kept.
const (
	massShare   = 0.5
	massMinimum = 20
)

// Options of a build.
type Options struct {
	Now time.Time
	// AllowMassChange lets a source drop more than the guard allows (a
	// person checked the source).
	AllowMassChange bool
	Log             func(format string, args ...any)
}

// Build returns the next snapshot. prev may be nil (first build). It fails
// only when no source could be read.
func Build(ctx context.Context, prev *bundle.Snapshot, sources []source.Source, client *fetch.Client, opt Options) (*bundle.Snapshot, error) {
	if prev == nil {
		prev = bundle.NewSnapshot()
	}
	log := opt.Log
	if log == nil {
		log = func(string, ...any) {}
	}
	now := opt.Now.UTC().Truncate(time.Second)
	next := bundle.NewSnapshot()
	next.Sequence = prev.Sequence + 1
	ok := 0
	var failures []string
	seenSource := map[string]bool{}
	for _, src := range sources {
		meta := src.Meta()
		if seenSource[meta.Name] {
			return nil, fmt.Errorf("source %q configured twice", meta.Name)
		}
		seenSource[meta.Name] = true
		old := programsOf(prev, meta.Name)
		res, err := src.Collect(ctx, client)
		if err == nil {
			err = guard(res, old, opt.AllowMassChange)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			log("%s: %v; keeping its %d previous records", meta.Name, err, len(old))
			failures = append(failures, meta.Name+": "+err.Error())
			for _, p := range old {
				next.Programs[p.ID] = p
			}
			if s, had := prev.Source(meta.Name); had {
				s.Programs = len(old)
				next.Sources = append(next.Sources, s)
			}
			continue
		}
		ok++
		n := merge(prev, next, meta.Name, old, res, now, log)
		next.Sources = append(next.Sources, bundle.Source{Name: meta.Name, URL: meta.URL, AsOf: now, Terms: meta.Terms,
			Licence: meta.Licence, Attribution: meta.Attribution, Programs: n})
		log("%s: %d programs (%d skipped records, %d unreadable kept)", meta.Name, n, res.Skipped, len(res.Unknown))
	}
	// Programs of sources no longer configured are kept as they are; a
	// source is removed from the feed on purpose, in code review.
	for id, p := range prev.Programs {
		if !seenSource[p.Source] {
			next.Programs[id] = p
		}
	}
	for _, s := range prev.Sources {
		if !seenSource[s.Name] {
			next.Sources = append(next.Sources, s)
		}
	}
	if ok == 0 {
		return nil, fmt.Errorf("no source could be read (%s)", strings.Join(failures, "; "))
	}
	sort.Slice(next.Sources, func(i, j int) bool { return next.Sources[i].Name < next.Sources[j].Name })
	sortChanges(next.Changes)
	return next, next.Validate()
}

func programsOf(s *bundle.Snapshot, name string) map[string]model.Program {
	out := map[string]model.Program{}
	for id, p := range s.Programs {
		if p.Source == name {
			out[id] = p
		}
	}
	return out
}

func guard(res *source.Result, old map[string]model.Program, allow bool) error {
	open := 0
	for _, p := range old {
		if p.Status != model.StatusClosed {
			open++
		}
	}
	got := len(res.Programs) + len(res.Unknown)
	if !allow && open >= massMinimum && float64(got) < float64(open)*massShare {
		return fmt.Errorf("refusing: %d programs now, %d before (rerun with --allow-mass-change after checking the source)", got, open)
	}
	return nil
}

// merge folds one source's result into next and returns how many programs
// of the source next holds.
func merge(prev, next *bundle.Snapshot, name string, old map[string]model.Program, res *source.Result, now time.Time, log func(string, ...any)) int {
	seq := next.Sequence
	add := func(c model.Change) {
		c.Sequence = seq
		next.Changes = append(next.Changes, c)
	}
	seen := map[string]bool{}
	for _, id := range res.Unknown {
		if p, had := old[id]; had {
			next.Programs[id] = p
			seen[id] = true
		}
	}
	for _, p := range res.Programs {
		if seen[p.ID] {
			continue
		}
		if p.Source != name {
			log("%s: program %s claims source %q; skipped", name, p.ID, p.Source)
			continue
		}
		model.Normalize(&p)
		was, had := old[p.ID]
		p.LastSeen = now
		if had {
			p.FirstSeen = was.FirstSeen
			changes := diff(was, p)
			if len(changes) > 0 {
				p.LastChanged = now
			} else {
				p.LastChanged = was.LastChanged
			}
			if err := p.Validate(); err != nil {
				log("%s: %v; keeping the previous record", name, err)
				next.Programs[p.ID] = was
				seen[p.ID] = true
				continue
			}
			for _, c := range changes {
				add(c)
			}
		} else {
			p.FirstSeen, p.LastChanged = now, now
			if err := p.Validate(); err != nil {
				log("%s: %v; skipped", name, err)
				continue
			}
			add(model.Change{Program: p.ID, Kind: model.ChangeProgramAdded})
		}
		next.Programs[p.ID] = p
		seen[p.ID] = true
	}
	ids := make([]string, 0, len(old))
	for id := range old {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		p := old[id]
		switch {
		case p.Status != model.StatusClosed:
			at := now
			p.Status, p.ClosedAt, p.LastChanged = model.StatusClosed, &at, now
			next.Programs[id] = p
			add(model.Change{Program: id, Kind: model.ChangeProgramClosed})
		case now.Sub(*p.ClosedAt) > DropAfter:
			add(model.Change{Program: id, Kind: model.ChangeProgramDropped})
		default:
			next.Programs[id] = p
		}
		seen[id] = true
	}
	n := 0
	for _, p := range next.Programs {
		if p.Source == name {
			n++
		}
	}
	return n
}

// diff lists what changed between two records of one program.
func diff(a, b model.Program) []model.Change {
	var out []model.Change
	id := b.ID
	switch {
	case a.Status == model.StatusClosed && b.Status != model.StatusClosed:
		out = append(out, model.Change{Program: id, Kind: model.ChangeProgramReopened})
	case a.Status != b.Status:
		out = append(out, model.Change{Program: id, Kind: model.ChangeStatus, Fields: []string{"status"}})
	}
	out = append(out, diffTargets(id, "in", a.InScope, b.InScope)...)
	out = append(out, diffTargets(id, "out", a.OutOfScope, b.OutOfScope)...)
	if !reflect.DeepEqual(a.Rules, b.Rules) {
		out = append(out, model.Change{Program: id, Kind: model.ChangeRules, Fields: diffFields(a.Rules, b.Rules)})
	}
	if a.Terms.URL != b.Terms.URL || a.Terms.SHA256 != b.Terms.SHA256 {
		out = append(out, model.Change{Program: id, Kind: model.ChangeTerms})
	}
	var fields []string
	for name, eq := range map[string]bool{
		"name": a.Name == b.Name, "url": a.URL == b.URL, "platform": a.Platform == b.Platform, "type": a.Type == b.Type,
		"scope_published": a.ScopePublished == b.ScopePublished, "contact": a.Contact == b.Contact,
		"rejected": reflect.DeepEqual(a.Rejected, b.Rejected),
	} {
		if !eq {
			fields = append(fields, name)
		}
	}
	if len(fields) > 0 {
		sort.Strings(fields)
		out = append(out, model.Change{Program: id, Kind: model.ChangeProgramModified, Fields: fields})
	}
	return out
}

func diffTargets(id, scope string, a, b []model.Target) []model.Change {
	key := func(t model.Target) string { return t.Type + "\x00" + t.Value }
	before := map[string]model.Target{}
	for _, t := range a {
		before[key(t)] = t
	}
	var out []model.Change
	after := map[string]bool{}
	for _, t := range b {
		t := t
		after[key(t)] = true
		was, had := before[key(t)]
		switch {
		case !had:
			out = append(out, model.Change{Program: id, Kind: model.ChangeTargetAdded, Scope: scope, Target: &t})
		case !reflect.DeepEqual(was, t):
			out = append(out, model.Change{Program: id, Kind: model.ChangeTargetModified, Scope: scope, Target: &t, Fields: diffFields(was, t)})
		}
	}
	for _, t := range a {
		t := t
		if !after[key(t)] {
			out = append(out, model.Change{Program: id, Kind: model.ChangeTargetRemoved, Scope: scope, Target: &t})
		}
	}
	return out
}

// diffFields names the JSON fields that differ between two structs.
func diffFields(a, b any) []string {
	var ma, mb map[string]json.RawMessage
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	_ = json.Unmarshal(ja, &ma)
	_ = json.Unmarshal(jb, &mb)
	var out []string
	for k, v := range ma {
		if string(mb[k]) != string(v) {
			out = append(out, k)
		}
	}
	for k := range mb {
		if _, ok := ma[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > model.MaxChangeFields {
		out = out[:model.MaxChangeFields]
	}
	return out
}

var kindOrder = map[string]int{
	model.ChangeProgramAdded: 0, model.ChangeProgramReopened: 1, model.ChangeStatus: 2, model.ChangeProgramModified: 3,
	model.ChangeRules: 4, model.ChangeTerms: 5, model.ChangeTargetAdded: 6, model.ChangeTargetModified: 7,
	model.ChangeTargetRemoved: 8, model.ChangeProgramClosed: 9, model.ChangeProgramDropped: 10,
}

func sortChanges(cs []model.Change) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Program != b.Program {
			return a.Program < b.Program
		}
		if kindOrder[a.Kind] != kindOrder[b.Kind] {
			return kindOrder[a.Kind] < kindOrder[b.Kind]
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		var ta, tb string
		if a.Target != nil {
			ta = a.Target.Type + "\x00" + a.Target.Value
		}
		if b.Target != nil {
			tb = b.Target.Type + "\x00" + b.Target.Value
		}
		return ta < tb
	})
}
