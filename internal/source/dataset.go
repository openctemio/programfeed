package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// Shared parts of the adapters that read public aggregate datasets on
// GitHub: datasets that copy the program listings of bug-bounty platforms
// into JSON files. A dataset record is never trusted more than the
// dataset: the program page must sit on the platform's own host, every
// record names the dataset repository, the commit it was read at and the
// original platform and page, and every target is normalised by the same
// scope rules as any other source.
//
// Reading a dataset does not make its records publishable: the platform a
// record came from has its own publish policy (see the policy package).

const (
	githubAPI = "https://api.github.com"
	githubRaw = "https://raw.githubusercontent.com"

	maxDatasetBytes = 32 << 20
	// datasetDeadline bounds one large dataset download (the idle-read guard
	// still fails a stalled one early).
	datasetDeadline   = 5 * time.Minute
	maxDatasetRecords = 20000
	maxCommitListSize = 1 << 20
)

// githubDataset locates files of one dataset repository at one commit.
type githubDataset struct {
	Repo    string // owner/name
	Ref     string // branch to resolve when Commit is empty
	Commit  string // pinned commit; resolved from Ref when empty
	APIBase string // githubAPI unless a test overrides it
	RawBase string // githubRaw unless a test overrides it
}

func (g githubDataset) apiBase() string {
	if g.APIBase != "" {
		return g.APIBase
	}
	return githubAPI
}

func (g githubDataset) rawBase() string {
	if g.RawBase != "" {
		return g.RawBase
	}
	return githubRaw
}

// resolve returns the commit every file of this run is read at. All files
// of a run come from one commit, and the raw URLs contain it, so the bytes
// read are the bytes of that commit.
func (g githubDataset) resolve(ctx context.Context, c *fetch.Client) (string, error) {
	if g.Commit != "" {
		if !commitHex.MatchString(g.Commit) {
			return "", fmt.Errorf("%s: pinned commit %q is not a 40-character commit id", g.Repo, g.Commit)
		}
		return g.Commit, nil
	}
	ref := g.Ref
	if ref == "" {
		ref = "main"
	}
	u := fmt.Sprintf("%s/repos/%s/commits?per_page=1&sha=%s", g.apiBase(), g.Repo, url.QueryEscape(ref))
	resp, err := c.Get(ctx, u, maxCommitListSize)
	if err != nil {
		return "", fmt.Errorf("%s: resolving %s: %w", g.Repo, ref, err)
	}
	var list []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(resp.Body, &list); err != nil || len(list) != 1 || !commitHex.MatchString(list[0].SHA) {
		return "", fmt.Errorf("%s: %s does not resolve to a commit", g.Repo, ref)
	}
	return list[0].SHA, nil
}

func (g githubDataset) rawURL(commit, path string) string {
	return fmt.Sprintf("%s/%s/%s/%s", g.rawBase(), g.Repo, commit, path)
}

var commitHex = regexp.MustCompile(`^[0-9a-f]{40}$`)

// platformSpec describes one platform an aggregate dataset covers.
type platformSpec struct {
	name  string
	hosts []string // hosts of the platform's own program pages
}

// onPlatform reports whether a program page is an https URL on one of the
// platform's hosts.
func (p platformSpec) onPlatform(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, ok := range p.hosts {
		if h == ok || strings.HasSuffix(h, "."+ok) {
			return true
		}
	}
	return false
}

// wanted reports whether only is empty or names the platform.
func wanted(only []string, platform string) bool {
	if len(only) == 0 {
		return true
	}
	for _, o := range only {
		if o == platform {
			return true
		}
	}
	return false
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// Kinds of asset a platform declares, as far as the feed distinguishes them.
const (
	kindAuto   = ""
	kindMobile = "mobile"
	kindSource = "source"
	kindOpaque = "opaque" // hardware, devices and the like: kept as text
)

// classify turns an asset a platform lists into a typed target. The
// platform's declared kind decides only where the value cannot say what it
// is (an app id looks like a host name); everything else follows the shape
// of the value. The scope rules refuse what is not acceptable afterwards.
func classify(kind, value string) (string, string) {
	v := strings.TrimSpace(value)
	switch kind {
	case kindMobile:
		return model.TargetMobileApp, v
	case kindSource:
		return model.TargetSourceRepo, v
	case kindOpaque:
		return model.TargetOther, v
	}
	switch {
	case v == "" || strings.ContainsAny(v, " \t\r\n"):
		return model.TargetOther, v
	case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
		return model.TargetURL, v
	case strings.HasPrefix(v, "*."):
		return model.TargetWildcard, v
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return model.TargetCIDR, v
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return model.TargetIP, v
	}
	if hostnameRE.MatchString(v) {
		return model.TargetDomain, v
	}
	return model.TargetOther, v
}

// decodeRecords splits a JSON array into records, enforcing the dataset
// caps. A file that is not an array is an error: the dataset changed shape
// and the whole source is kept as it was.
func decodeRecords(body []byte, what string) ([]json.RawMessage, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if len(raw) > maxDatasetRecords {
		return nil, fmt.Errorf("%s: %d records, over the cap of %d", what, len(raw), maxDatasetRecords)
	}
	return raw, nil
}
