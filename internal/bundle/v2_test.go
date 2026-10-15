package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/transfer"
	sdkbundle "github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/programfeed/internal/model"
)

// big returns a snapshot of n programs (so the programs stream spans
// several chunks); target changes the scope of the program with index
// changed (-1: none).
func big(seq uint64, n, changed int) *Snapshot {
	s := NewSnapshot()
	s.Sequence = seq
	s.Sources = []Source{{Name: "disclose", URL: "https://openctem.io/list.json", AsOf: t0, Licence: "CC0-1.0"}}
	for i := range n {
		tgt := fmt.Sprintf("p%05d.openctem.io", i)
		if i == changed {
			tgt = "changed.openctem.io"
		}
		p := program(fmt.Sprintf("disclose:p%05d", i), tgt)
		s.Programs[p.ID] = p
	}
	return s
}

func manifestV2(t *testing.T, dir, name string) sdkbundle.Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var m sdkbundle.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func chunkHashes(m sdkbundle.Manifest, stream string) []string {
	var out []string
	for _, s := range m.Streams {
		if s.Name == stream {
			for _, c := range s.Chunks {
				out = append(out, c.SHA256)
			}
		}
	}
	return out
}

func writeAt(t *testing.T, prev, next *Snapshot) string {
	t.Helper()
	dir := t.TempDir()
	if _, _, _, err := Write(dir, prev, next, WriteOptions{Now: t0}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestV2UnchangedInputGivesIdenticalChunks(t *testing.T) {
	a := writeAt(t, nil, big(1, 6000, -1))
	b := writeAt(t, nil, big(1, 6000, -1))
	ma, mb := manifestV2(t, a, unsignedSnapshotV2), manifestV2(t, b, unsignedSnapshotV2)
	ha, hb := chunkHashes(ma, "programs"), chunkHashes(mb, "programs")
	if len(ha) < 2 {
		t.Fatalf("%d chunks: the stream did not split", len(ha))
	}
	if strings.Join(ha, ",") != strings.Join(hb, ",") {
		t.Fatal("same input, different chunks")
	}
	// A later release with the same programs shares every programs chunk.
	c := writeAt(t, nil, big(2, 6000, -1))
	if strings.Join(chunkHashes(manifestV2(t, c, unsignedSnapshotV2), "programs"), ",") != strings.Join(ha, ",") {
		t.Fatal("same programs at a later sequence, different chunks")
	}
}

func TestV2OneChangedProgramChangesOneChunk(t *testing.T) {
	a := writeAt(t, nil, big(1, 6000, -1))
	b := writeAt(t, nil, big(2, 6000, 3100))
	ha := chunkHashes(manifestV2(t, a, unsignedSnapshotV2), "programs")
	hb := chunkHashes(manifestV2(t, b, unsignedSnapshotV2), "programs")
	if len(ha) != len(hb) {
		t.Fatalf("chunk count moved: %d -> %d", len(ha), len(hb))
	}
	diff := 0
	for i := range ha {
		if ha[i] != hb[i] {
			diff++
		}
	}
	if diff != 1 {
		t.Fatalf("%d chunks changed, want 1", diff)
	}
}

func TestV1OutputUnchangedByV2(t *testing.T) {
	k := newKeys(t)
	dir := build(t, k, snapshot(1, "b.openctem.io"), snapshot(2, "c.openctem.io"))
	for _, n := range []string{"latest.dsse.json", "snapshot.manifest.dsse.json", "delta.manifest.dsse.json", "keyset.dsse.json",
		"snapshot-programs.jsonl.gz", "snapshot-changes.jsonl.gz", "delta-programs.jsonl.gz", "delta-changes.jsonl.gz"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("v1 file %s missing: %v", n, err)
		}
	}
	if _, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, AppliedSeq: 1, Now: time.Now()}); err != nil {
		t.Fatalf("v1 verify: %v", err)
	}
	// No unsigned v2 payload is left in a signed release.
	for _, n := range []string{unsignedSnapshotV2, unsignedDeltaV2, "snapshot.manifest.json", "latest.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Fatalf("unsigned %s left in a signed release", n)
		}
	}
}

type collect struct {
	progs, changes map[string]bool
	completes      int
}

func (c *collect) ApplyChunk(_ context.Context, ch *sdkbundle.Chunk, _ sdkbundle.State) error {
	return ch.Records(func(line []byte) error {
		var r struct {
			ID      string `json:"id"`
			Program string `json:"program"`
			Kind    string `json:"kind"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		if r.ID != "" {
			c.progs[r.ID] = true
		} else {
			c.changes[r.Program+"/"+r.Kind] = true
		}
		return nil
	})
}

func (c *collect) Complete(context.Context, *sdkbundle.Manifest, sdkbundle.State) error {
	c.completes++
	return nil
}

func TestV2RoundTripWithSDKConsumer(t *testing.T) {
	k := newKeys(t)
	next := big(2, 3000, -1)
	next.Changes = []model.Change{{Sequence: 2, Program: "disclose:p00007", Kind: model.ChangeProgramAdded}}
	dir := t.TempDir()
	if _, _, _, err := Write(dir, big(1, 3000, 5), next, WriteOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err != nil {
		t.Fatal(err)
	}
	v, err := VerifyDir(dir, VerifyOptions{PinnedRoot: k.rootID, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(dir, v.KeySet, time.Now()); err != nil {
		t.Fatalf("VerifyV2: %v", err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	f, err := transfer.New(transfer.Config{Origins: []transfer.Origin{{URL: srv.URL}}, CacheDir: t.TempDir(), Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	col := &collect{progs: map[string]bool{}, changes: map[string]bool{}}
	pub, _ := k.priv.Public().(ed25519.PublicKey)
	c, err := sdkbundle.NewConsumer(sdkbundle.Config{Feed: FeedV2, Fetcher: f, Verifier: sdkbundle.NewEd25519Verifier(pub),
		Checkpoint: sdkbundle.FileCheckpoint{Path: filepath.Join(t.TempDir(), "cp.json")}, Applier: col})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != sdkbundle.KindSnapshot || len(col.progs) != 3000 || !col.changes["disclose:p00007/"+model.ChangeProgramAdded] || col.completes != 1 {
		t.Fatalf("res %+v progs %d changes %v", res, len(col.progs), col.changes)
	}
}

func TestV2LocalOnlyIsUnsignedAndNotSignable(t *testing.T) {
	dir := t.TempDir()
	snap := big(1, 10, -1)
	if _, _, _, err := Write(dir, nil, snap, WriteOptions{Now: t0, Collector: Collector{LocalOnly: true}}); err != nil {
		t.Fatal(err)
	}
	m := manifestV2(t, dir, unsignedSnapshotV2)
	var meta V2Meta
	if err := json.Unmarshal(m.Meta, &meta); err != nil || !meta.Collector.LocalOnly {
		t.Fatalf("meta %s: local_only not set (%v)", m.Meta, err)
	}
	k := newKeys(t)
	if err := Sign(dir, k.priv, k.keyset, k.rootID, time.Now()); err == nil {
		t.Fatal("signed a local-only bundle")
	}
	names := []string{}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		if strings.HasSuffix(n, ".dsse.json") {
			t.Fatalf("signed file %s in a local-only bundle", n)
		}
	}
}
