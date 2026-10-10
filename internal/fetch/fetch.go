// Package fetch is the collector's only way to the network: a polite HTTP
// client that names itself and its contact, honours robots.txt, spaces
// requests to one host, makes conditional requests from an on-disk cache,
// caps response sizes and refuses to connect to non-public addresses (a
// seed list or a redirect must not point the collector at internal
// services).
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/openctemio/programfeed/internal/model"
)

// Product is the robots.txt product token of the collector.
const Product = "openctem-programfeed"

// UserAgent names the collector, where it lives and who to contact.
func UserAgent(version string) string {
	return Product + "/" + version + " (+https://github.com/openctemio/programfeed; security@openctem.io)"
}

// Errors callers act on.
var (
	ErrDisallowed = errors.New("robots.txt disallows this URL")
	ErrNotFound   = errors.New("not found")
	ErrTooLarge   = errors.New("response over the size cap")
)

const maxRobotsBytes = 512 << 10

// Options configure a client.
type Options struct {
	UserAgent   string
	CacheDir    string        // conditional requests; empty disables the cache
	MinInterval time.Duration // between two requests to one host
	Timeout     time.Duration // per request
	// AllowPrivate lets tests talk to httptest servers on loopback. Never
	// set in the collector.
	AllowPrivate bool
	// DialOverride sends every connection to this address (tests only,
	// with AllowPrivate).
	DialOverride string
}

// Client is safe for concurrent use.
type Client struct {
	opt  Options
	http *http.Client

	mu     sync.Mutex
	next   map[string]time.Time // host -> earliest next request
	robots map[string]*robotsRules
}

// Response is a fetched body.
type Response struct {
	URL       string // final URL after redirects
	Body      []byte
	FetchedAt time.Time
	Cached    bool // 304: the body is the cached one
}

// New returns a client.
func New(opt Options) *Client {
	if opt.MinInterval == 0 {
		opt.MinInterval = time.Second
	}
	if opt.Timeout == 0 {
		opt.Timeout = 30 * time.Second
	}
	c := &Client{opt: opt, next: map[string]time.Time{}, robots: map[string]*robotsRules{}}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		if opt.AllowPrivate {
			return nil
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !model.PublicAddr(ap.Addr()) {
			return fmt.Errorf("refusing to connect to non-public address %s", address)
		}
		return nil
	}}
	dial := dialer.DialContext
	if opt.DialOverride != "" && opt.AllowPrivate {
		dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, opt.DialOverride)
		}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: opt.Timeout,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}
	c.http = &http.Client{Transport: transport, Timeout: opt.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("more than 3 redirects")
			}
			if req.URL.Scheme != "https" && !(opt.AllowPrivate && req.URL.Scheme == "http") {
				return errors.New("redirect to a non-https URL")
			}
			// A robots.txt fetch is not itself subject to robots.txt (a
			// site that redirects everything would otherwise recurse).
			if req.Context().Value(robotsFetch{}) == nil {
				if ok, err := c.allowed(req.Context(), req.URL); err != nil || !ok {
					return ErrDisallowed
				}
			}
			return c.wait(req.Context(), req.URL.Host)
		}}
	return c
}

// Get fetches rawURL (at most maxBytes) after checking robots.txt.
func (c *Client) Get(ctx context.Context, rawURL string, maxBytes int64) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && !(c.opt.AllowPrivate && u.Scheme == "http")) || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("fetch: refusing URL %q", rawURL)
	}
	ok, err := c.allowed(ctx, u)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s: %w", rawURL, ErrDisallowed)
	}
	return c.get(ctx, u, maxBytes, true)
}

type cacheEntry struct {
	URL          string `json:"url"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Body         []byte `json:"body"`
}

func (c *Client) cachePath(u string) string {
	if c.opt.CacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(u))
	return filepath.Join(c.opt.CacheDir, hex.EncodeToString(sum[:])+".json")
}

func (c *Client) get(ctx context.Context, u *url.URL, maxBytes int64, useCache bool) (*Response, error) {
	if err := c.wait(ctx, u.Host); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.opt.UserAgent)
	req.Header.Set("From", "security@openctem.io")
	var cached *cacheEntry
	path := ""
	if useCache {
		path = c.cachePath(u.String())
	}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var e cacheEntry
			if json.Unmarshal(b, &e) == nil && e.URL == u.String() && int64(len(e.Body)) <= maxBytes {
				cached = &e
				if e.ETag != "" {
					req.Header.Set("If-None-Match", e.ETag)
				}
				if e.LastModified != "" {
					req.Header.Set("If-Modified-Since", e.LastModified)
				}
			}
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	now := time.Now().UTC().Truncate(time.Second)
	switch {
	case resp.StatusCode == http.StatusNotModified && cached != nil:
		return &Response{URL: u.String(), Body: cached.Body, FetchedAt: now, Cached: true}, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, fmt.Errorf("%s: %w", u, ErrNotFound)
	case resp.StatusCode != http.StatusOK:
		return nil, &StatusError{URL: u.String(), Code: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%s: %w (%d bytes)", u, ErrTooLarge, maxBytes)
	}
	if path != "" && (resp.Header.Get("ETag") != "" || resp.Header.Get("Last-Modified") != "") {
		e := cacheEntry{URL: u.String(), ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), Body: body}
		if b, err := json.Marshal(e); err == nil {
			_ = os.MkdirAll(c.opt.CacheDir, 0o755)
			_ = os.WriteFile(path, b, 0o644)
		}
	}
	return &Response{URL: resp.Request.URL.String(), Body: body, FetchedAt: now}, nil
}

// wait blocks until a request to host is polite.
func (c *Client) wait(ctx context.Context, host string) error {
	c.mu.Lock()
	now := time.Now()
	at := c.next[host]
	if at.Before(now) {
		at = now
	}
	c.next[host] = at.Add(c.opt.MinInterval)
	c.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// allowed checks robots.txt of u's origin (fetched once per run). A missing
// robots.txt (4xx) allows everything; an unreachable one (network error,
// 5xx) disallows everything, as RFC 9309 asks.
func (c *Client) allowed(ctx context.Context, u *url.URL) (bool, error) {
	origin := u.Scheme + "://" + u.Host
	c.mu.Lock()
	r, ok := c.robots[origin]
	c.mu.Unlock()
	if !ok {
		ru, _ := url.Parse(origin + "/robots.txt")
		resp, err := c.get(context.WithValue(ctx, robotsFetch{}, true), ru, maxRobotsBytes, false)
		switch {
		case err == nil:
			r = parseRobots(string(resp.Body), Product)
		case errors.Is(err, ErrNotFound) || isStatus(err, 400, 499):
			r = &robotsRules{}
		case errors.Is(err, ErrTooLarge):
			r = &robotsRules{}
		case ctx.Err() != nil:
			return false, ctx.Err()
		default:
			r = &robotsRules{disallowAll: true}
		}
		c.mu.Lock()
		c.robots[origin] = r
		c.mu.Unlock()
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return r.allows(path), nil
}

type robotsFetch struct{}

// StatusError is an unexpected HTTP status.
type StatusError struct {
	URL  string
	Code int
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.URL, e.Code) }

func isStatus(err error, lo, hi int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code >= lo && se.Code <= hi
}
