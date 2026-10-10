// Command programfeed builds, signs and verifies OpenCTEM program bundles
// (public bug-bounty and vulnerability-disclosure programs), and manages
// the signing keys.
//
//	programfeed build  --out DIR [--prev DIR] [--root-key-id ID] [--cache DIR] [--sources a,b] [--policy FILE] [--local-only] [--seed-file FILE] [--allow-mass-change]
//	programfeed sign   --dir DIR --keyset FILE --root-key-id ID     (key in $PROGRAMFEED_SIGNING_KEY)
//	programfeed verify --dir DIR --root-key-id ID [--applied N] [--allow-expired]
//	programfeed keys root-init --out FILE
//	programfeed keys gen --out FILE
//	programfeed keys sign-keyset --root FILE --key PUBLIC_KEY [--key ...] --version N [--days 180] --out FILE
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/openctemio/programfeed/internal/bundle"
	"github.com/openctemio/programfeed/internal/collect"
	"github.com/openctemio/programfeed/internal/dsse"
	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/source"
	"github.com/openctemio/programfeed/policy"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "programfeed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: programfeed build|sign|verify|keys ...")
	}
	switch args[0] {
	case "build":
		return cmdBuild(ctx, args[1:])
	case "sign":
		return cmdSign(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	case "keys":
		return cmdKeys(args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

// sources returns the configured adapters, in order.
//
// only limits the dataset adapters to platforms the publish policy allows
// (nil = everything, for a local-only build); a dataset adapter with
// nothing left to read is left out.
func sources(names, seedFile string, only []string, localOnly bool) ([]source.Source, error) {
	if localOnly {
		only = nil
	}
	var out []source.Source
	for _, n := range strings.Split(names, ",") {
		switch strings.TrimSpace(n) {
		case "diodb":
			out = append(out, source.DioDB{})
		case "securitytxt":
			st := source.SecurityTxt{Progress: func(done, total int) { logf("securitytxt: %d/%d domains", done, total) }}
			if seedFile != "" {
				b, err := os.ReadFile(seedFile)
				if err != nil {
					return nil, err
				}
				st.Extra = source.ParseSeedFile(b)
			}
			out = append(out, st)
		case "bounty-targets":
			if b := source.NewBountyTargets(only); localOnly || len(intersect(only, source.BountyTargetsPlatforms())) > 0 {
				out = append(out, b)
			} else {
				logf("bounty-targets: no platform may be published, not fetched")
			}
		case "pd-bounty":
			if len(only) > 0 || localOnly {
				out = append(out, source.NewPDBounty(only))
			} else {
				logf("pd-bounty: no platform may be published, not fetched")
			}
		case "":
		default:
			return nil, fmt.Errorf("unknown source %q", n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no source selected")
	}
	return out, nil
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
			}
		}
	}
	return out
}

func cmdBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	out := fs.String("out", "", "output directory")
	prevDir := fs.String("prev", "", "previous release (verified before use)")
	root := fs.String("root-key-id", os.Getenv("PROGRAMFEED_ROOT_KEY_ID"), "pinned root key id")
	mass := fs.Bool("allow-mass-change", false, "accept a source that suddenly lost more than half of its programs")
	cache := fs.String("cache", "", "HTTP cache directory for conditional requests")
	names := fs.String("sources", "diodb,securitytxt,bounty-targets,pd-bounty", "comma-separated adapters")
	policyFile := fs.String("policy", "", "publish policy file (default: the compiled-in policy/platforms.json)")
	localOnly := fs.Bool("local-only", false, "ignore the publish policy and write an UNSIGNED local bundle that must not be published")
	seedFile := fs.String("seed-file", "seeds/securitytxt.txt", "extra security.txt seed domains (empty to skip)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("build: --out is required")
	}
	pol := policy.Default()
	if *policyFile != "" {
		b, err := os.ReadFile(*policyFile)
		if err != nil {
			return err
		}
		if pol, err = policy.Parse(b); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	if !*localOnly && *prevDir != "" && bundle.IsLocalOnly(*prevDir) {
		return errors.New("build: --prev is a local-only bundle; a publishable build needs a signed release")
	}
	srcs, err := sources(*names, *seedFile, pol.PublishablePlatforms(), *localOnly)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var prev *bundle.Snapshot
	if *prevDir != "" && *localOnly {
		// Continue the previous local bundle's sequence (snapshot-only,
		// unsigned): the platform importer refuses non-increasing sequences.
		var err error
		if prev, err = bundle.ReadLocal(*prevDir); err != nil {
			return fmt.Errorf("previous local bundle: %w", err)
		}
		logf("previous local bundle: sequence %d, %d programs", prev.Sequence, len(prev.Programs))
	} else if *prevDir != "" {
		v, err := bundle.VerifyDir(*prevDir, bundle.VerifyOptions{PinnedRoot: *root, Now: now, AllowExpired: true, SkipRecordChk: true})
		if err != nil {
			return fmt.Errorf("previous release: %w", err)
		}
		if prev, err = bundle.ReadRecords(*prevDir, v.Snapshot); err != nil {
			return fmt.Errorf("previous release: %w", err)
		}
		logf("previous release: sequence %d, %d programs", prev.Sequence, len(prev.Programs))
	}
	var removed []string
	if !*localOnly {
		prev, removed = pol.PrunePrev(prev)
	}
	client := fetch.New(fetch.Options{UserAgent: fetch.UserAgent(version), CacheDir: *cache, Timeout: 20 * time.Second})
	next, err := collect.Build(ctx, prev, srcs, client, collect.Options{Now: now, AllowMassChange: *mass, Log: logf})
	if err != nil {
		return err
	}
	if *localOnly {
		logf("LOCAL-ONLY: the publish policy was not applied; this bundle is unsigned and must not be published")
	} else {
		full := len(next.Programs)
		next = pol.Filter(next, removed)
		logf("publish policy: %d of %d programs publishable", len(next.Programs), full)
	}
	writePrev := prev
	if *localOnly {
		writePrev = nil // snapshot-only: no delta is written for a local bundle
	}
	snap, delta, _, err := bundle.Write(*out, writePrev, next, bundle.WriteOptions{Now: now,
		Collector: bundle.Collector{Version: version, Commit: os.Getenv("GITHUB_SHA"), LocalOnly: *localOnly}})
	if err != nil {
		return err
	}
	st := snap.Stats
	logf("built sequence %d: %d programs (%d open, %d bounty), %d targets, %d rejected targets, %d changes",
		snap.Sequence, st.Programs, st.Open, st.Bounty, st.Targets, st.Rejected, st.Changes)
	if delta != nil {
		logf("delta from %d: %d programs (+%d added, %d closed, %d dropped)", delta.BaseSequence, delta.Stats.Programs,
			delta.Stats.Added, delta.Stats.Closed, delta.Stats.Dropped)
	}
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	dir := fs.String("dir", "", "bundle directory")
	keyset := fs.String("keyset", "keys/keyset.dsse.json", "key set envelope")
	root := fs.String("root-key-id", os.Getenv("PROGRAMFEED_ROOT_KEY_ID"), "pinned root key id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("PROGRAMFEED_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("sign: PROGRAMFEED_SIGNING_KEY must be a base64 32-byte Ed25519 seed")
	}
	ks, err := os.ReadFile(*keyset)
	if err != nil {
		return err
	}
	return bundle.Sign(*dir, ed25519.NewKeyFromSeed(seed), ks, *root, time.Now())
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("dir", "", "bundle directory")
	root := fs.String("root-key-id", os.Getenv("PROGRAMFEED_ROOT_KEY_ID"), "pinned root key id")
	applied := fs.Uint64("applied", 0, "last applied sequence")
	expired := fs.Bool("allow-expired", false, "accept an expired bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := bundle.VerifyDir(*dir, bundle.VerifyOptions{PinnedRoot: *root, AppliedSeq: *applied, Now: time.Now(), AllowExpired: *expired})
	if err != nil {
		return err
	}
	if bundle.HasV2(*dir) {
		if err := bundle.VerifyV2(*dir, v.KeySet, time.Now()); err != nil {
			return err
		}
		logf("verified bundle v2 (sequence %d)", v.Latest.Sequence)
	}
	logf("verified sequence %d (snapshot %d programs, %d targets; key set v%d)", v.Latest.Sequence,
		v.Snapshot.Stats.Programs, v.Snapshot.Stats.Targets, v.KeySet.Version)
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("keys: root-init|gen|sign-keyset")
	}
	switch args[0] {
	case "root-init", "gen":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		out := fs.String("out", "", "file to write the private seed to (mode 0600; keep a root offline)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("keys: --out is required")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("key id:     %s\npublic key: %s\nseed file:  %s\n", dsse.KeyID(pub), base64.StdEncoding.EncodeToString(pub), *out)
		return nil
	case "sign-keyset":
		fs := flag.NewFlagSet("sign-keyset", flag.ContinueOnError)
		rootFile := fs.String("root", "", "root seed file")
		ver := fs.Uint64("version", 0, "key set version (higher than the current one)")
		days := fs.Int("days", 180, "validity in days (at most 180)")
		out := fs.String("out", "keys/keyset.dsse.json", "output")
		var keys multi
		fs.Var(&keys, "key", "base64 public key of an online signing key (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		raw, err := os.ReadFile(*rootFile)
		if err != nil {
			return err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("keys: the root file is not a base64 32-byte seed")
		}
		pubs := make([]ed25519.PublicKey, 0, len(keys))
		for _, k := range keys {
			b, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(b) != ed25519.PublicKeySize {
				return fmt.Errorf("keys: %q is not a base64 Ed25519 public key", k)
			}
			pubs = append(pubs, b)
		}
		env, err := dsse.SignKeySet(ed25519.NewKeyFromSeed(seed), *ver, time.Now(), time.Duration(*days)*24*time.Hour, pubs)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, env, 0o644)
	}
	return fmt.Errorf("keys: unknown command %q", args[0])
}
