package bundle

// Bundle format v2 (OpenCTEM RFC-070): the same records as v1, in
// content-addressed gzip JSON Lines chunks split by record id, listed in a
// signed manifest per kind and a signed pointer. It is written next to the
// v1 files for one release and read by the SDK's bundle consumer.
//
// Layout note: a build writes the chunks and the UNSIGNED v2 manifests
// (snapshot.v2.manifest.json, delta.v2.manifest.json); the signing step
// wraps them in DSSE envelopes and writes the signed pointer, because the
// pointer pins the digest of each signed manifest.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	sdkbundle "github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/programfeed/internal/dsse"
	"github.com/openctemio/programfeed/internal/model"
)

// FeedV2 is the feed name of the v2 bundle (its DSSE payload types).
const FeedV2 = "programfeed"

// V2 file names of unsigned payloads (the signed ones are the SDK's
// sdkbundle.ManifestFile and sdkbundle.PointerFile).
const (
	unsignedSnapshotV2 = "snapshot.v2.manifest.json"
	unsignedDeltaV2    = "delta.v2.manifest.json"
)

// V2Meta is the manifest's meta block: what v1 keeps beside its file list.
type V2Meta struct {
	Sources   []Source  `json:"sources"`
	Stats     Stats     `json:"stats"`
	Collector Collector `json:"collector"`
}

// rawSigner "signs" by returning the payload: the writer then stores the
// unsigned manifest, which the signing step wraps later.
type rawSigner struct{}

func (rawSigner) Sign(_ string, payload []byte) ([]byte, error) { return payload, nil }

func unsignedName(kind string) string {
	if kind == KindDelta {
		return unsignedDeltaV2
	}
	return unsignedSnapshotV2
}

// recordLine is one record as one JSON line (no HTML escaping, like v1).
func recordLine(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// changeIDs gives each change a record id that ascends with (program,
// position in the log): "<program>#<n>". '#' sorts before every character
// a program id holds, so ids of one program stay together and in order.
func changeIDs(changes []model.Change) (ids []string, order []int) {
	order = make([]int, len(changes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return changes[order[a]].Program < changes[order[b]].Program })
	ids = make([]string, len(changes))
	n, prog := 0, ""
	for k, i := range order {
		if changes[i].Program != prog {
			prog, n = changes[i].Program, 0
		}
		ids[k] = fmt.Sprintf("%s#%06d", prog, n)
		n++
	}
	return ids, order
}

func writeKindV2(dir, kind string, s *Snapshot, ids []string, base uint64, now time.Time, meta V2Meta) error {
	w, err := sdkbundle.NewWriter(dir, sdkbundle.WriterOptions{Feed: FeedV2, Sequence: s.Sequence, Kind: kind, BaseSequence: base})
	if err != nil {
		return err
	}
	if err := w.Stream("programs"); err != nil {
		return err
	}
	for _, id := range ids {
		line, err := recordLine(s.Programs[id])
		if err != nil {
			return err
		}
		if err := w.Add(id, line); err != nil {
			return err
		}
	}
	if err := w.Stream("changes"); err != nil {
		return err
	}
	cids, order := changeIDs(s.Changes)
	for k, i := range order {
		line, err := recordLine(s.Changes[i])
		if err != nil {
			return err
		}
		if err := w.Add(cids[k], line); err != nil {
			return err
		}
	}
	rawMeta, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, _, err = w.Finish(rawMeta, now, now.Add(Validity), rawSigner{})
	if err != nil {
		return err
	}
	// Finish wrote the payload under the signed name; keep it as unsigned.
	return os.Rename(filepath.Join(dir, sdkbundle.ManifestFile(kind)), filepath.Join(dir, unsignedName(kind)))
}

// WriteV2 writes the v2 chunks and unsigned manifests of next (and of the
// delta from prev when prev is not nil) into dir, next to the v1 files.
// snap and delta are the v1 manifests of the same build (stats, sources).
func WriteV2(dir string, prev, next *Snapshot, snap, delta *Manifest) error {
	meta := func(m *Manifest) V2Meta { return V2Meta{Sources: m.Sources, Stats: m.Stats, Collector: m.Collector} }
	if err := writeKindV2(dir, KindSnapshot, next, next.SortedIDs(), 0, snap.CreatedAt, meta(snap)); err != nil {
		return fmt.Errorf("bundle v2 snapshot: %w", err)
	}
	if prev != nil && delta != nil {
		if err := writeKindV2(dir, KindDelta, next, next.ChangedIDs(), prev.Sequence, delta.CreatedAt, meta(delta)); err != nil {
			return fmt.Errorf("bundle v2 delta: %w", err)
		}
	}
	return nil
}

// signV2 signs the unsigned v2 manifests in dir and writes the signed
// pointer. The key and key set were already checked by Sign.
func signV2(dir string, priv ed25519.PrivateKey) error {
	signer := sdkbundle.Ed25519Signer{Key: priv}
	var ptr sdkbundle.Pointer
	for _, kind := range []string{KindSnapshot, KindDelta} {
		payload, err := os.ReadFile(filepath.Join(dir, unsignedName(kind)))
		if errors.Is(err, os.ErrNotExist) && kind == KindDelta {
			continue
		}
		if err != nil {
			return err
		}
		var m sdkbundle.Manifest
		if err := json.Unmarshal(payload, &m); err != nil {
			return fmt.Errorf("%s: %w", unsignedName(kind), err)
		}
		var meta V2Meta
		if json.Unmarshal(m.Meta, &meta) == nil && meta.Collector.LocalOnly {
			return errors.New("refusing to sign a local-only bundle: it was built without the publish policy")
		}
		env, err := signer.Sign(sdkbundle.ManifestPayloadType(FeedV2), payload)
		if err != nil {
			return err
		}
		name := sdkbundle.ManifestFile(kind)
		if err := os.WriteFile(filepath.Join(dir, name), env, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(env)
		ref := sdkbundle.FileRef{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(env))}
		if kind == KindSnapshot {
			ptr = sdkbundle.Pointer{Feed: FeedV2, Sequence: m.Sequence, Snapshot: ref, CreatedAt: m.CreatedAt, ExpiresAt: m.ExpiresAt}
		} else {
			ptr.Delta, ptr.BaseSequence = &ref, m.BaseSequence
		}
		if err := os.Remove(filepath.Join(dir, unsignedName(kind))); err != nil {
			return err
		}
	}
	if ptr.Sequence == 0 {
		return errors.New("no v2 snapshot manifest to sign")
	}
	return sdkbundle.WritePointer(dir, ptr, signer)
}

// HasV2 reports whether dir holds a signed v2 pointer.
func HasV2(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, sdkbundle.PointerFile))
	return err == nil
}

// VerifyV2 checks the v2 files of dir the way the SDK consumer does: the
// pointer and manifests against the key set's keys, the manifests against
// the digests the pointer pins, and every chunk against its manifest entry.
func VerifyV2(dir string, ks *dsse.KeySet, now time.Time) error {
	var pubs []ed25519.PublicKey
	for _, k := range ks.Keys {
		pub, err := k.Decode()
		if err != nil {
			return err
		}
		pubs = append(pubs, pub)
	}
	ver := sdkbundle.NewEd25519Verifier(pubs...)
	read := func(name string, max int64) ([]byte, error) { return readCapped(filepath.Join(dir, name), max) }
	raw, err := read(sdkbundle.PointerFile, MaxManifestBytes)
	if err != nil {
		return err
	}
	payload, err := ver.Verify(raw, sdkbundle.PointerPayloadType(FeedV2))
	if err != nil {
		return fmt.Errorf("v2 pointer: %w", err)
	}
	var ptr sdkbundle.Pointer
	if err := dsse.DecodeStrict(payload, &ptr); err != nil {
		return fmt.Errorf("v2 pointer: %w", err)
	}
	if err := ptr.Validate(FeedV2, now, sdkbundle.Limits{}); err != nil {
		return err
	}
	refs := []sdkbundle.FileRef{ptr.Snapshot}
	if ptr.Delta != nil {
		refs = append(refs, *ptr.Delta)
	}
	for _, ref := range refs {
		env, err := read(ref.Name, MaxManifestBytes)
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(env); int64(len(env)) != ref.Size || hex.EncodeToString(sum[:]) != ref.SHA256 {
			return fmt.Errorf("v2 %s does not match the pointer", ref.Name)
		}
		mp, err := ver.Verify(env, sdkbundle.ManifestPayloadType(FeedV2))
		if err != nil {
			return fmt.Errorf("v2 %s: %w", ref.Name, err)
		}
		var m sdkbundle.Manifest
		if err := dsse.DecodeStrict(mp, &m); err != nil {
			return fmt.Errorf("v2 %s: %w", ref.Name, err)
		}
		if err := m.Validate(FeedV2, now, sdkbundle.Limits{}); err != nil {
			return err
		}
		if m.Sequence != ptr.Sequence {
			return fmt.Errorf("v2 %s: sequence %d, pointer %d", ref.Name, m.Sequence, ptr.Sequence)
		}
		for _, c := range m.Chunks() {
			if err := checkFile(filepath.Join(dir, sdkbundle.ChunkFile(c.Ref.SHA256)), File{Name: c.Ref.SHA256, SHA256: c.Ref.SHA256, Size: c.Ref.Size}); err != nil {
				return fmt.Errorf("v2 chunk: %w", err)
			}
		}
	}
	return nil
}
