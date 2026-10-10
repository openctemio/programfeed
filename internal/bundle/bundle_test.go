package bundle

import (
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/programfeed/internal/dsse"
	"github.com/openctemio/programfeed/internal/model"
)

type keys struct {
	rootID string
	priv   ed25519.PrivateKey
	keyset []byte
}

func newKeys(t *testing.T) keys {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks, err := dsse.SignKeySet(root, 1, time.Now().Add(-time.Hour), 90*24*time.Hour, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	return keys{rootID: dsse.KeyID(rootPub), priv: priv, keyset: ks}
}

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func program(id, target string) model.Program {
	p := model.Program{
		ID: id, Source: "disclose", Platform: "self-hosted", Name: id, URL: "https://openctem.io/security",
		Type: model.TypeVDP, Status: model.StatusOpen,
		InScope:    []model.Target{{Type: model.TargetDomain, Value: target, Confidence: model.ConfidenceInferred}},
		OutOfScope: []model.Target{},
		Terms:      model.Terms{URL: "https://openctem.io/security"},
		Provenance: model.Provenance{Source: "disclose", SourceURL: "https://openctem.io/list.json", FetchedAt: t0},
		FirstSeen:  t0, LastSeen: t0, LastChanged: t0,
	}
	model.Normalize(&p)
	return p
}

func snapshot(seq uint64, target string) *Snapshot {
	s := NewSnapshot()
	s.Sequence = seq
	s.Sources = []Source{{Name: "disclose", URL: "https://openctem.io/list.json", AsOf: t0, Licence: "CC0-1.0"}}
	a, b := program("disclose:a", "a.openctem.io"), program("disclose:b", target)
	s.Programs[a.ID], s.Programs[b.ID] = a, b
	tg := b.InScope[0]
	s.Changes = []model.Change{{Sequence: seq, Program: b.ID, Kind: model.ChangeTargetAdded, Scope: "in", Target: &tg}}
	return s
}

func build(t *testing.T, k keys, prev, next *Snapshot) string {
	t.Helper()
	dir := t.TempDir()
	if _, _, _, err := Write(dir, prev, next, WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRoundTrip(t *testing.T) {
	k := newKeys(t)
	prev, next := snapshot(1, "b.openctem.io"), snapshot(2, "c.openctem.io")
	dir := build(t, k, prev, next)
	v, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 1, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if v.Latest.Sequence != 2 || v.Latest.Tag != "v1-2" || v.Delta == nil || v.Delta.BaseSequence != 1 {
		t.Fatalf("%+v", v.Latest)
	}
	if v.Snapshot.Stats.Programs != 2 || v.Delta.Stats.Programs != 1 || v.Delta.Stats.Changes != 1 {
		t.Fatalf("stats %+v / %+v", v.Snapshot.Stats, v.Delta.Stats)
	}
	got, err := ReadRecords(dir, v.Snapshot)
	if err != nil || len(got.Programs) != 2 || got.Programs["disclose:b"].InScope[0].Value != "c.openctem.io" {
		t.Fatalf("snapshot %v %+v", err, got)
	}
	d, err := ReadRecords(dir, *v.Delta)
	if err != nil || len(d.Programs) != 1 || len(d.Changes) != 1 {
		t.Fatalf("delta %v %+v", err, d)
	}
	dir2 := build(t, k, prev, next)
	for _, f := range v.Snapshot.Files {
		a, _ := os.ReadFile(filepath.Join(dir, f.Name))
		b, _ := os.ReadFile(filepath.Join(dir2, f.Name))
		if string(a) != string(b) {
			t.Errorf("%s differs between builds", f.Name)
		}
	}
}

func TestVerifyRefuses(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	now := time.Now()
	cases := map[string]struct {
		mut func(t *testing.T, dir string)
		opt VerifyOptions
	}{
		"rollback":            {nil, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 5, Now: now}},
		"replay same":         {nil, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 3, Now: now}},
		"expired":             {nil, VerifyOptions{PinnedRoot: k.rootID, Now: now.Add(8 * 24 * time.Hour)}},
		"other root":          {nil, VerifyOptions{PinnedRoot: other.rootID, Now: now}},
		"no pinned root":      {nil, VerifyOptions{Now: now}},
		"key set rolled back": {nil, VerifyOptions{PinnedRoot: k.rootID, MinKeySetVer: 2, Now: now}},
		"tampered file": {func(t *testing.T, dir string) {
			p := filepath.Join(dir, FileName(KindSnapshot, "programs"))
			b, _ := os.ReadFile(p)
			b[len(b)/2] ^= 0xff
			_ = os.WriteFile(p, b, 0o644)
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"swapped key set": {func(t *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, KeySetFile), other.keyset, 0o644)
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"vulnerability feed key set": {func(t *testing.T, dir string) {
			// A key set of another feed (other payload type) is refused even
			// under the same root.
			raw, _ := os.ReadFile(filepath.Join(dir, KeySetFile))
			var env dsse.Envelope
			_ = json.Unmarshal(raw, &env)
			env.PayloadType = "application/vnd.openctem.vulnfeed.keyset+json"
			b, _ := json.Marshal(env)
			_ = os.WriteFile(filepath.Join(dir, KeySetFile), b, 0o644)
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"pointer signed by a stranger": {func(t *testing.T, dir string) {
			resignJSON(t, dir, LatestFile, LatestPayloadType, other.priv, func(m map[string]any) {})
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"pointer names another sequence": {func(t *testing.T, dir string) {
			resignJSON(t, dir, LatestFile, LatestPayloadType, k.priv, func(m map[string]any) { m["sequence"] = 9; m["tag"] = "v1-9" })
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"manifest valid for a year": {func(t *testing.T, dir string) {
			resignJSON(t, dir, "snapshot.manifest.dsse.json", ManifestPayloadType, k.priv, func(m map[string]any) {
				m["expires_at"] = now.Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
			})
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
		"unknown field": {func(t *testing.T, dir string) {
			resignJSON(t, dir, LatestFile, LatestPayloadType, k.priv, func(m map[string]any) { m["extra"] = 1 })
		}, VerifyOptions{PinnedRoot: k.rootID, Now: now}},
	}
	for name, c := range cases {
		dir := build(t, k, snapshot(2, "b.openctem.io"), snapshot(3, "c.openctem.io"))
		if c.mut != nil {
			c.mut(t, dir)
		}
		if _, err := VerifyDir(dir, c.opt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Poisoned records under a valid signature and correct hashes are refused:
// the importer re-validates every record.
func TestPoisonedRecordsRefused(t *testing.T) {
	k := newKeys(t)
	good := program("disclose:x", "x.openctem.io")
	line := func(mut func(m map[string]any)) string {
		b, _ := json.Marshal(good)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mut(m)
		out, _ := json.Marshal(m)
		return string(out)
	}
	target := func(typ, value string) func(m map[string]any) {
		return func(m map[string]any) {
			m["in_scope"] = []any{map[string]any{"type": typ, "value": value, "confidence": "published"}}
		}
	}
	cases := map[string]string{
		"public suffix wildcard": line(target("wildcard", "*.com")),
		"private range":          line(target("cidr", "10.0.0.0/8")),
		"huge range":             line(target("cidr", "1.0.0.0/8")),
		"metadata address":       line(target("ip", "169.254.169.254")),
		"bare TLD":               line(target("domain", "com")),
		"javascript url":         line(func(m map[string]any) { m["url"] = "javascript:alert(1)" }),
		"closed without time":    line(func(m map[string]any) { m["status"] = "closed" }),
		"extra field":            line(func(m map[string]any) { m["sql"] = "x" }),
		"duplicate":              line(func(map[string]any) {}) + "\n" + line(func(map[string]any) {}),
	}
	for name, l := range cases {
		dir := build(t, k, nil, snapshot(1, "b.openctem.io"))
		replaceFile(t, dir, k, FileName(KindSnapshot, "programs"), l+"\n", strings.Count(l, "\n")+1)
		if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A change naming a program that is not in the bundle is refused.
	dir := build(t, k, nil, snapshot(1, "b.openctem.io"))
	replaceFile(t, dir, k, FileName(KindSnapshot, "changes"), `{"sequence":1,"program":"disclose:ghost","kind":"program_added"}`+"\n", 1)
	if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()}); err == nil {
		t.Error("change of an absent program accepted")
	}
	// A wrong record count is refused too.
	dir = build(t, k, nil, snapshot(1, "b.openctem.io"))
	replaceFile(t, dir, k, FileName(KindSnapshot, "programs"), line(func(map[string]any) {})+"\n", 5)
	if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "records") {
		t.Errorf("record count: %v", err)
	}
}

func TestWriteRefusesInvalidSnapshot(t *testing.T) {
	s := snapshot(1, "b.openctem.io")
	p := s.Programs["disclose:a"]
	p.InScope = []model.Target{{Type: model.TargetWildcard, Value: "*.com", Confidence: model.ConfidencePublished}}
	s.Programs["disclose:a"] = p
	if _, _, _, err := Write(t.TempDir(), nil, s, WriteOptions{Now: time.Now()}); err == nil {
		t.Fatal("invalid snapshot written")
	}
}

func TestSignRefusesKeyOutsideKeySet(t *testing.T) {
	k := newKeys(t)
	_, stranger, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	if _, _, _, err := Write(dir, nil, snapshot(1, "b.openctem.io"), WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, stranger, k.keyset, k.rootID, time.Now()); err == nil {
		t.Fatal("signed with a key outside the key set")
	}
}

// replaceFile rewrites one record file, fixes its hash/size/count in the
// manifest and re-signs the manifest: only record validation can catch it.
func replaceFile(t *testing.T, dir string, k keys, name, content string, records int) {
	t.Helper()
	p := filepath.Join(dir, name)
	f, _ := os.Create(p)
	gz := gzip.NewWriter(f)
	_, _ = gz.Write([]byte(content))
	_ = gz.Close()
	_ = f.Close()
	b, _ := os.ReadFile(p)
	sum := sha256.Sum256(b)
	resignJSON(t, dir, "snapshot.manifest.dsse.json", ManifestPayloadType, k.priv, func(m map[string]any) {
		for _, fi := range m["files"].([]any) {
			fm := fi.(map[string]any)
			if fm["name"] == name {
				fm["sha256"], fm["size"], fm["records"] = hex.EncodeToString(sum[:]), len(b), records
			}
		}
	})
}

func resignJSON(t *testing.T, dir, file, payloadType string, priv ed25519.PrivateKey, mut func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	var env dsse.Envelope
	_ = json.Unmarshal(raw, &env)
	var m map[string]any
	_ = json.Unmarshal(env.Payload, &m)
	mut(m)
	payload, _ := json.Marshal(m)
	out, _ := dsse.Sign(priv, payloadType, payload)
	_ = os.WriteFile(filepath.Join(dir, file), out, 0o644)
}
