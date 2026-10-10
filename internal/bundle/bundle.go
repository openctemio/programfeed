// Package bundle builds, signs, reads and verifies program bundles: JSON
// Lines files per record type, a signed manifest per snapshot and delta,
// and a signed latest pointer. The layout, envelopes, key set and checks
// are the ones of the OpenCTEM vulnerability feed, so one verifier serves
// both (only the payload types and record files differ).
package bundle

import (
	"bufio"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openctemio/programfeed/internal/dsse"
	"github.com/openctemio/programfeed/internal/model"
)

// Schemas, payload types and file names.
const (
	ManifestSchema      = "openctem.programfeed/v1"
	LatestSchema        = "openctem.programfeed.latest/v1"
	ManifestPayloadType = "application/vnd.openctem.programfeed.manifest+json"
	LatestPayloadType   = "application/vnd.openctem.programfeed.latest+json"

	KindSnapshot = "snapshot"
	KindDelta    = "delta"

	LatestFile   = "latest.dsse.json"
	KeySetFile   = "keyset.dsse.json"
	ManifestFile = "%s.manifest.dsse.json" // snapshot | delta

	Validity = 7 * 24 * time.Hour
)

// Caps (the importer applies the same).
const (
	MaxManifestBytes     = 1 << 20
	MaxFileBytes         = 128 << 20
	MaxDecompressedBytes = 1 << 30
	MaxRecordBytes       = 4 << 20
)

// Record files of a bundle, in import order. A snapshot holds every
// program and this run's change log; a delta holds the programs that
// changed (complete new records) and the same change log.
var recordFiles = []string{"programs", "changes"}

// FileName is the name of a record file of a kind.
func FileName(kind, records string) string { return kind + "-" + records + ".jsonl.gz" }

// Source names one upstream source, its terms and how much it gave.
type Source struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	AsOf        time.Time `json:"as_of"` // last successful read
	Terms       string    `json:"terms"`
	Licence     string    `json:"licence"`
	Attribution string    `json:"attribution"`
	Programs    int       `json:"programs"`
}

// File is one record file of a manifest.
type File struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Records int    `json:"records"`
}

// Stats summarises a bundle.
type Stats struct {
	Programs int `json:"programs"`
	Open     int `json:"open"`
	Bounty   int `json:"bounty"`
	Targets  int `json:"targets"`
	Rejected int `json:"rejected"`
	Changes  int `json:"changes"`
	Added    int `json:"added"`
	Closed   int `json:"closed"`
	Dropped  int `json:"dropped"`
}

// Collector identifies the build.
type Collector struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	// LocalOnly marks a bundle built without the publish policy (it may
	// hold records of platforms that do not allow redistribution). It is
	// never signed and never published.
	LocalOnly bool `json:"local_only,omitempty"`
}

// Manifest is the signed description of a snapshot or a delta.
type Manifest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Kind         string    `json:"kind"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Sources      []Source  `json:"sources"`
	Files        []File    `json:"files"`
	Stats        Stats     `json:"stats"`
	Collector    Collector `json:"collector"`
}

// Latest is the signed pointer to the newest bundle.
type Latest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Tag          string    `json:"tag"`
	Snapshot     string    `json:"snapshot"`
	Delta        string    `json:"delta,omitempty"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Tag is the release tag of a sequence.
func Tag(sequence uint64) string { return fmt.Sprintf("v1-%d", sequence) }

// Snapshot is the complete program set plus the change log of the run
// that produced it.
type Snapshot struct {
	Sequence uint64
	Sources  []Source
	Programs map[string]model.Program
	Changes  []model.Change
}

// NewSnapshot returns an empty snapshot.
func NewSnapshot() *Snapshot { return &Snapshot{Programs: map[string]model.Program{}} }

// Source returns a source by name.
func (s *Snapshot) Source(name string) (Source, bool) {
	for _, src := range s.Sources {
		if src.Name == name {
			return src, true
		}
	}
	return Source{}, false
}

// SortedIDs returns the program ids in order.
func (s *Snapshot) SortedIDs() []string {
	ids := make([]string, 0, len(s.Programs))
	for id := range s.Programs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ChangedIDs returns the ids of programs present in the snapshot that the
// change log touches, in order.
func (s *Snapshot) ChangedIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, c := range s.Changes {
		if _, ok := s.Programs[c.Program]; ok && !seen[c.Program] {
			seen[c.Program] = true
			ids = append(ids, c.Program)
		}
	}
	sort.Strings(ids)
	return ids
}

// Validate checks every record of the snapshot.
func (s *Snapshot) Validate() error {
	if len(s.Programs) > model.MaxPrograms {
		return fmt.Errorf("%d programs, over the cap of %d", len(s.Programs), model.MaxPrograms)
	}
	for _, id := range s.SortedIDs() {
		p := s.Programs[id]
		if p.ID != id {
			return fmt.Errorf("program %s filed under %s", p.ID, id)
		}
		if err := p.Validate(); err != nil {
			return err
		}
	}
	for i := range s.Changes {
		c := &s.Changes[i]
		if err := c.Validate(); err != nil {
			return err
		}
		if c.Sequence != s.Sequence {
			return fmt.Errorf("change of %s has sequence %d, the snapshot is %d", c.Program, c.Sequence, s.Sequence)
		}
		if _, ok := s.Programs[c.Program]; ok == (c.Kind == model.ChangeProgramDropped) {
			return fmt.Errorf("change %s of %s: a dropped program must be absent, any other present", c.Kind, c.Program)
		}
	}
	return nil
}

func (s *Snapshot) stats(ids []string) Stats {
	st := Stats{Programs: len(ids), Changes: len(s.Changes)}
	for _, id := range ids {
		p := s.Programs[id]
		if p.Status == model.StatusOpen {
			st.Open++
		}
		if p.OffersBounty {
			st.Bounty++
		}
		st.Targets += len(p.InScope) + len(p.OutOfScope)
		st.Rejected += len(p.Rejected)
	}
	for _, c := range s.Changes {
		switch c.Kind {
		case model.ChangeProgramAdded:
			st.Added++
		case model.ChangeProgramClosed:
			st.Closed++
		case model.ChangeProgramDropped:
			st.Dropped++
		}
	}
	return st
}

// WriteOptions describe a build.
type WriteOptions struct {
	Now       time.Time
	Collector Collector
}

// Write writes the snapshot of next and, when prev is not nil, the delta
// from prev, with unsigned manifests (payloads) and the latest pointer
// payload, into dir.
func Write(dir string, prev, next *Snapshot, opt WriteOptions) (snap, delta *Manifest, latest *Latest, err error) {
	if err := next.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("refusing to publish an invalid bundle: %w", err)
	}
	if prev != nil && next.Sequence <= prev.Sequence {
		return nil, nil, nil, fmt.Errorf("sequence %d is not after %d", next.Sequence, prev.Sequence)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, nil, err
	}
	now := opt.Now.UTC().Truncate(time.Second)
	all := next.SortedIDs()
	snap = &Manifest{Schema: ManifestSchema, Sequence: next.Sequence, Kind: KindSnapshot, CreatedAt: now,
		ExpiresAt: now.Add(Validity), Sources: next.Sources, Collector: opt.Collector, Stats: next.stats(all)}
	if snap.Files, err = writeFiles(dir, KindSnapshot, next, all); err != nil {
		return nil, nil, nil, err
	}
	latest = &Latest{Schema: LatestSchema, Sequence: next.Sequence, Tag: Tag(next.Sequence),
		Snapshot: fmt.Sprintf(ManifestFile, KindSnapshot), CreatedAt: now, ExpiresAt: now.Add(Validity)}
	if prev != nil {
		ids := next.ChangedIDs()
		delta = &Manifest{Schema: ManifestSchema, Sequence: next.Sequence, Kind: KindDelta, BaseSequence: prev.Sequence,
			CreatedAt: now, ExpiresAt: now.Add(Validity), Sources: next.Sources, Collector: opt.Collector, Stats: next.stats(ids)}
		if delta.Files, err = writeFiles(dir, KindDelta, next, ids); err != nil {
			return nil, nil, nil, err
		}
		latest.Delta, latest.BaseSequence = fmt.Sprintf(ManifestFile, KindDelta), prev.Sequence
	}
	if err := writeJSON(filepath.Join(dir, "snapshot.manifest.json"), snap); err != nil {
		return nil, nil, nil, err
	}
	if delta != nil {
		if err := writeJSON(filepath.Join(dir, "delta.manifest.json"), delta); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := writeJSON(filepath.Join(dir, "latest.json"), latest); err != nil {
		return nil, nil, nil, err
	}
	return snap, delta, latest, nil
}

func writeFiles(dir, kind string, s *Snapshot, ids []string) ([]File, error) {
	var files []File
	for _, rf := range recordFiles {
		name := FileName(kind, rf)
		var n int
		f, err := writeGz(filepath.Join(dir, name), func(enc *json.Encoder) error {
			switch rf {
			case "programs":
				for _, id := range ids {
					if err := enc.Encode(s.Programs[id]); err != nil {
						return err
					}
					n++
				}
			case "changes":
				for _, c := range s.Changes {
					if err := enc.Encode(c); err != nil {
						return err
					}
					n++
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		f.Name, f.Records = name, n
		files = append(files, f)
	}
	return files, nil
}

func writeGz(path string, fill func(*json.Encoder) error) (File, error) {
	out, err := os.Create(path)
	if err != nil {
		return File{}, err
	}
	h := sha256.New()
	counter := &countWriter{}
	gz, _ := gzip.NewWriterLevel(io.MultiWriter(out, h, counter), gzip.BestCompression)
	gz.ModTime = time.Unix(0, 0)
	bw := bufio.NewWriterSize(gz, 1<<20)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	if err := fill(enc); err != nil {
		out.Close()
		return File{}, err
	}
	if err := bw.Flush(); err != nil {
		out.Close()
		return File{}, err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return File{}, err
	}
	if err := out.Close(); err != nil {
		return File{}, err
	}
	if counter.n > MaxFileBytes {
		return File{}, fmt.Errorf("%s is %d bytes, over the %d cap", filepath.Base(path), counter.n, MaxFileBytes)
	}
	return File{SHA256: hex.EncodeToString(h.Sum(nil)), Size: counter.n}, nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Sign wraps the unsigned manifests and latest pointer in dir in DSSE
// envelopes signed by priv, and copies the key set next to them. The
// signing key must be listed in the key set.
func Sign(dir string, priv ed25519.PrivateKey, keyset []byte, pinnedRoot string, now time.Time) error {
	if raw, err := os.ReadFile(filepath.Join(dir, "snapshot.manifest.json")); err == nil {
		var m struct {
			Collector Collector `json:"collector"`
		}
		if json.Unmarshal(raw, &m) == nil && m.Collector.LocalOnly {
			return errors.New("refusing to sign a local-only bundle: it was built without the publish policy")
		}
	}
	ks, err := dsse.VerifyKeySet(keyset, pinnedRoot, 0, now)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	listed := false
	for _, k := range ks.Keys {
		if k.KeyID == dsse.KeyID(pub) {
			listed = true
		}
	}
	if !listed {
		return fmt.Errorf("the signing key %s is not in the key set", dsse.KeyID(pub))
	}
	pairs := []struct{ in, out, typ string }{
		{"snapshot.manifest.json", fmt.Sprintf(ManifestFile, KindSnapshot), ManifestPayloadType},
		{"delta.manifest.json", fmt.Sprintf(ManifestFile, KindDelta), ManifestPayloadType},
		{"latest.json", LatestFile, LatestPayloadType},
	}
	for _, p := range pairs {
		payload, err := os.ReadFile(filepath.Join(dir, p.in))
		if errors.Is(err, os.ErrNotExist) && p.in == "delta.manifest.json" {
			continue
		}
		if err != nil {
			return err
		}
		env, err := dsse.Sign(priv, p.typ, payload)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, p.out), env, 0o644); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(dir, p.in)); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, KeySetFile), keyset, 0o644)
}

// Stats summarises the whole snapshot.
func (s *Snapshot) Stats() Stats { return s.stats(s.SortedIDs()) }
