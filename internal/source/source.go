// Package source holds the adapters, one per upstream source. An adapter
// reads its source through the polite fetch client only, and turns what it
// read into programs; it never validates scope itself (the collector
// normalises every program the same way) and never sets timestamps other
// than provenance.
package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// Meta describes a source and its terms; it is carried in every manifest.
type Meta struct {
	Name        string // id prefix of its programs, [a-z0-9-]
	URL         string
	Terms       string
	Licence     string
	Attribution string
}

// Result is what one run of an adapter produced.
type Result struct {
	Programs []model.Program
	// Unknown lists ids whose state could not be read this run (a host
	// that did not answer, for example). The collector keeps their
	// previous record instead of closing them.
	Unknown []string
	// Skipped counts source records that were not programs (no policy,
	// malformed record …), for the log.
	Skipped int
}

// Source is one adapter.
type Source interface {
	Meta() Meta
	// Collect reads the whole source. An error means the source as a
	// whole could not be read; the collector then keeps every previous
	// record of the source unchanged.
	Collect(ctx context.Context, c *fetch.Client) (*Result, error)
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// Slug turns a name into an id slug ([a-z0-9-], at most 100 characters).
func Slug(name string) string {
	s := strings.Trim(slugRE.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 100 {
		s = strings.TrimRight(s[:100], "-")
	}
	return s
}

// UniqueSlugs gives every name a stable slug; names whose slugs collide
// (or are empty) all get a short hash of the name appended, so the result
// does not depend on the order of the source.
func UniqueSlugs(names []string) map[string]string {
	count := map[string]int{}
	for _, n := range names {
		count[Slug(n)]++
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		s := Slug(n)
		if count[s] > 1 || s == "" {
			sum := sha256.Sum256([]byte(n))
			s = strings.TrimLeft(s+"-"+hex.EncodeToString(sum[:4]), "-")
		}
		out[n] = s
	}
	return out
}
