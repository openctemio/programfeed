package bundle

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/programfeed/internal/dsse"
	"github.com/openctemio/programfeed/internal/model"
)

// Verified is a bundle directory whose signatures, freshness and file
// hashes checked out.
type Verified struct {
	KeySet   *dsse.KeySet
	Latest   Latest
	Snapshot Manifest
	Delta    *Manifest
}

// VerifyOptions are the consumer's state.
type VerifyOptions struct {
	PinnedRoot    string
	MinKeySetVer  uint64
	AppliedSeq    uint64
	Now           time.Time
	AllowExpired  bool // the previous release, read while building
	SkipRecordChk bool
}

// VerifyDir checks a bundle the way the platform importer does: key set
// (pinned root, version), latest pointer and manifests (key set, schema,
// sequence, expiry), every file's size and hash, and every record.
func VerifyDir(dir string, opt VerifyOptions) (*Verified, error) {
	ksRaw, err := readCapped(filepath.Join(dir, KeySetFile), dsse.MaxKeySetBytes)
	if err != nil {
		return nil, err
	}
	ks, err := dsse.VerifyKeySet(ksRaw, opt.PinnedRoot, opt.MinKeySetVer, opt.Now)
	if err != nil {
		return nil, err
	}
	v := &Verified{KeySet: ks}
	if err := verifyJSON(ks, filepath.Join(dir, LatestFile), LatestPayloadType, &v.Latest); err != nil {
		return nil, err
	}
	l := v.Latest
	switch {
	case l.Schema != LatestSchema:
		return nil, fmt.Errorf("latest: schema %q", l.Schema)
	case l.Sequence <= opt.AppliedSeq:
		return nil, fmt.Errorf("latest: sequence %d is not after the applied %d (rollback refused)", l.Sequence, opt.AppliedSeq)
	case !opt.AllowExpired && !l.ExpiresAt.After(opt.Now):
		return nil, fmt.Errorf("latest: expired at %s", l.ExpiresAt.Format(time.RFC3339))
	case l.Tag != Tag(l.Sequence):
		return nil, fmt.Errorf("latest: tag %q does not name sequence %d", l.Tag, l.Sequence)
	}
	if err := v.loadManifest(dir, l.Snapshot, KindSnapshot, &v.Snapshot, opt); err != nil {
		return nil, err
	}
	if l.Delta != "" {
		var d Manifest
		if err := v.loadManifest(dir, l.Delta, KindDelta, &d, opt); err != nil {
			return nil, err
		}
		if d.BaseSequence != l.BaseSequence || d.BaseSequence >= d.Sequence {
			return nil, fmt.Errorf("delta: base sequence %d does not match the pointer", d.BaseSequence)
		}
		v.Delta = &d
	}
	return v, nil
}

func (v *Verified) loadManifest(dir, name, kind string, m *Manifest, opt VerifyOptions) error {
	if name != fmt.Sprintf(ManifestFile, kind) {
		return fmt.Errorf("%s manifest name %q", kind, name)
	}
	if err := verifyJSON(v.KeySet, filepath.Join(dir, name), ManifestPayloadType, m); err != nil {
		return err
	}
	switch {
	case m.Schema != ManifestSchema:
		return fmt.Errorf("%s: schema %q", kind, m.Schema)
	case m.Kind != kind:
		return fmt.Errorf("%s: kind %q", kind, m.Kind)
	case m.Sequence != v.Latest.Sequence:
		return fmt.Errorf("%s: sequence %d, the pointer says %d", kind, m.Sequence, v.Latest.Sequence)
	case !opt.AllowExpired && !m.ExpiresAt.After(opt.Now):
		return fmt.Errorf("%s: expired", kind)
	case m.ExpiresAt.Sub(m.CreatedAt) > Validity:
		return fmt.Errorf("%s: valid for more than %s", kind, Validity)
	case len(m.Files) != len(recordFiles):
		return fmt.Errorf("%s: %d files", kind, len(m.Files))
	}
	for i, f := range m.Files {
		if f.Name != FileName(kind, recordFiles[i]) {
			return fmt.Errorf("%s: unexpected file %q", kind, f.Name)
		}
		if err := checkFile(filepath.Join(dir, f.Name), f); err != nil {
			return err
		}
	}
	if opt.SkipRecordChk {
		return nil
	}
	_, err := ReadRecords(dir, *m)
	return err
}

func verifyJSON(ks *dsse.KeySet, path, payloadType string, v any) error {
	raw, err := readCapped(path, MaxManifestBytes)
	if err != nil {
		return err
	}
	payload, err := dsse.VerifyWith(ks, raw, payloadType, MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if err := dsse.DecodeStrict(payload, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", filepath.Base(path), max)
	}
	return b, nil
}

func checkFile(path string, f File) error {
	if f.Size > MaxFileBytes || f.Size < 0 {
		return fmt.Errorf("%s: size %d over the cap", f.Name, f.Size)
	}
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%s: size or SHA-256 does not match the manifest", f.Name)
	}
	return nil
}

// ReadRecords reads and validates the record files of a verified manifest
// into a snapshot (for a delta: only the changed programs, plus the change
// log).
func ReadRecords(dir string, m Manifest) (*Snapshot, error) {
	s := NewSnapshot()
	s.Sequence, s.Sources = m.Sequence, m.Sources
	counts := map[string]int{}
	for _, f := range m.Files {
		var kind string
		for _, rf := range recordFiles {
			if f.Name == FileName(m.Kind, rf) {
				kind = rf
			}
		}
		err := eachLine(filepath.Join(dir, f.Name), func(line []byte) error {
			counts[kind]++
			switch kind {
			case "programs":
				var p model.Program
				if err := strictLine(line, &p); err != nil {
					return err
				}
				if err := p.Validate(); err != nil {
					return err
				}
				if _, dup := s.Programs[p.ID]; dup {
					return fmt.Errorf("program %s listed twice", p.ID)
				}
				if len(s.Programs) >= model.MaxPrograms {
					return fmt.Errorf("over %d programs", model.MaxPrograms)
				}
				s.Programs[p.ID] = p
			case "changes":
				var c model.Change
				if err := strictLine(line, &c); err != nil {
					return err
				}
				if err := c.Validate(); err != nil {
					return err
				}
				if len(s.Changes) >= 10*model.MaxPrograms {
					return errors.New("too many changes")
				}
				s.Changes = append(s.Changes, c)
			default:
				return errors.New("unexpected record file")
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if counts[kind] != f.Records {
			return nil, fmt.Errorf("%s: %d records, the manifest says %d", f.Name, counts[kind], f.Records)
		}
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if m.Kind == KindDelta {
		if ids := s.ChangedIDs(); len(ids) != len(s.Programs) {
			return nil, errors.New("delta: a program that no change names")
		}
	}
	return s, nil
}

func strictLine(line []byte, v any) error { return dsse.DecodeStrict(line, v) }

func eachLine(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(io.LimitReader(f, MaxFileBytes))
	if err != nil {
		return err
	}
	defer gz.Close()
	sc := bufio.NewScanner(&limited{r: gz, left: MaxDecompressedBytes})
	sc.Buffer(make([]byte, 64<<10), MaxRecordBytes)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// limited fails once more than left bytes are read (a decompression bomb).
type limited struct {
	r    io.Reader
	left int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("decompressed data over the cap")
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

// ReadLocal reads the previous UNSIGNED local-only bundle in dir (written by
// a --local-only build) so the next local build can continue its sequence.
// It checks schema, tag, file sizes and hashes and every record, and refuses
// anything that is not a local-only bundle (a signed release has DSSE
// envelopes in place of the plain pointer and manifest).
func ReadLocal(dir string) (*Snapshot, error) {
	var l Latest
	raw, err := readCapped(filepath.Join(dir, "latest.json"), 1<<20)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &l) != nil || l.Schema != LatestSchema {
		return nil, errors.New("not an unsigned local-only bundle (signed releases cannot seed a local build)")
	}
	if l.Tag != Tag(l.Sequence) || l.Snapshot != fmt.Sprintf(ManifestFile, KindSnapshot) {
		return nil, fmt.Errorf("latest: tag %q or snapshot %q does not match sequence %d", l.Tag, l.Snapshot, l.Sequence)
	}
	raw, err = readCapped(filepath.Join(dir, "snapshot.manifest.json"), 1<<20)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil || m.Schema != ManifestSchema || m.Kind != KindSnapshot {
		return nil, errors.New("snapshot manifest: not an unsigned manifest")
	}
	if !m.Collector.LocalOnly {
		return nil, errors.New("previous bundle is not local-only; a local build continues only a local-only bundle")
	}
	if m.Sequence != l.Sequence || len(m.Files) != len(recordFiles) {
		return nil, errors.New("snapshot manifest does not match the pointer")
	}
	for i, f := range m.Files {
		if f.Name != FileName(KindSnapshot, recordFiles[i]) {
			return nil, fmt.Errorf("unexpected file %q", f.Name)
		}
		if err := checkFile(filepath.Join(dir, f.Name), f); err != nil {
			return nil, err
		}
	}
	return ReadRecords(dir, m)
}

// IsLocalOnly reports whether dir holds an unsigned local-only bundle.
func IsLocalOnly(dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "snapshot.manifest.json"))
	if err != nil {
		return false
	}
	var m Manifest
	return json.Unmarshal(raw, &m) == nil && m.Collector.LocalOnly
}
