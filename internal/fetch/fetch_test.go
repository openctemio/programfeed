package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRobots(t *testing.T) {
	body := `
User-agent: *
Disallow: /private
Allow: /private/ok

User-agent: openctem-programfeed
User-agent: other
Disallow: /mine/*.json$
Allow: /

User-agent: badbot
Disallow: /
`
	r := parseRobots(body, Product)
	cases := map[string]bool{
		"/":               true,
		"/private":        true, // our group applies, not "*"
		"/mine/a.json":    false,
		"/mine/a.json?x":  true,
		"/mine/dir/b.txt": true,
	}
	for p, want := range cases {
		if got := r.allows(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
	star := parseRobots(body, "someone-else")
	if star.allows("/private/x") || !star.allows("/private/ok/1") || !star.allows("/public") {
		t.Error("star group rules")
	}
	if !parseRobots("", Product).allows("/anything") {
		t.Error("empty robots.txt must allow")
	}
}

func newClient(cacheDir string) *Client {
	return New(Options{UserAgent: UserAgent("test"), CacheDir: cacheDir, MinInterval: time.Millisecond, AllowPrivate: true})
}

func TestGetPoliteAndConditional(t *testing.T) {
	var hits, notModified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /secret\n"))
		case "/data.json":
			hits.Add(1)
			if !strings.Contains(r.UserAgent(), "security@openctem.io") || r.Header.Get("From") != "security@openctem.io" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if r.Header.Get("If-None-Match") == `"v1"` {
				notModified.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	c := newClient(t.TempDir())
	for i := 0; i < 2; i++ {
		r, err := c.Get(ctx, srv.URL+"/data.json", 1024)
		if err != nil || string(r.Body) != `{"ok":true}` || r.Cached != (i == 1) {
			t.Fatalf("get %d: %v %+v", i, err, r)
		}
	}
	if hits.Load() != 2 || notModified.Load() != 1 {
		t.Errorf("hits %d, 304s %d", hits.Load(), notModified.Load())
	}
	if _, err := c.Get(ctx, srv.URL+"/secret/x", 1024); !errors.Is(err, ErrDisallowed) {
		t.Errorf("robots: %v", err)
	}
	if _, err := c.Get(ctx, srv.URL+"/big", 1024); !errors.Is(err, ErrTooLarge) {
		t.Errorf("cap: %v", err)
	}
	if _, err := c.Get(ctx, srv.URL+"/nope", 1024); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
}

func TestRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer srv.Close()
	// The collector's client (AllowPrivate false) must not reach loopback,
	// whatever the URL says; it also refuses plain http.
	c := New(Options{UserAgent: UserAgent("test"), MinInterval: time.Millisecond})
	if _, err := c.Get(context.Background(), srv.URL+"/", 1024); err == nil {
		t.Fatal("fetched a loopback URL")
	}
	httpsURL := strings.Replace(srv.URL, "http://", "https://", 1)
	if _, err := c.Get(context.Background(), httpsURL+"/", 1024); err == nil {
		t.Fatal("connected to a loopback address")
	}
	if _, err := c.Get(context.Background(), "https://user:pw@openctem.io/", 1024); err == nil {
		t.Fatal("accepted credentials in URL")
	}
}

func TestUnreachableRobotsDisallows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()
	if _, err := newClient("").Get(context.Background(), srv.URL+"/x", 1024); !errors.Is(err, ErrDisallowed) {
		t.Fatalf("5xx robots.txt: %v", err)
	}
}

// A site that redirects every path (robots.txt included) to its home page
// must not make the robots.txt check recurse.
func TestRedirectEverythingTerminates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/home" {
			_, _ = w.Write([]byte("<html>home</html>"))
			return
		}
		http.Redirect(w, r, "/home", http.StatusFound)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := newClient("").Get(ctx, srv.URL+"/.well-known/security.txt", 1024)
	if ctx.Err() != nil {
		t.Fatal("robots.txt check recursed")
	}
	if err != nil || r.URL != srv.URL+"/home" {
		t.Fatalf("%v %+v", err, r)
	}
}

func slowServer(chunks int, gap time.Duration, stallAfter int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		fl := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			if stallAfter >= 0 && i == stallAfter {
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				return
			}
			_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
			fl.Flush()
			time.Sleep(gap)
		}
	}))
}

func TestSlowButSteadyBodyPasses(t *testing.T) {
	srv := slowServer(20, 25*time.Millisecond, -1) // ~500ms total, over Timeout
	defer srv.Close()
	c := New(Options{UserAgent: "t", MinInterval: time.Millisecond, AllowPrivate: true,
		Timeout: 200 * time.Millisecond, IdleTimeout: 300 * time.Millisecond})
	if _, err := c.Get(context.Background(), srv.URL+"/big", 1<<20); err == nil {
		t.Fatal("the default deadline must still bound the request")
	}
	resp, err := c.Get(WithDeadline(context.Background(), 5*time.Second), srv.URL+"/big", 1<<20)
	if err != nil || len(resp.Body) != 20*1024 {
		t.Fatalf("err=%v", err)
	}
}

func TestStalledBodyFails(t *testing.T) {
	srv := slowServer(20, time.Millisecond, 3)
	defer srv.Close()
	c := New(Options{UserAgent: "t", MinInterval: time.Millisecond, AllowPrivate: true,
		Timeout: time.Second, IdleTimeout: 150 * time.Millisecond})
	start := time.Now()
	_, err := c.Get(WithDeadline(context.Background(), time.Minute), srv.URL+"/big", 1<<20)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("a stall must fail fast: err=%v after %v", err, time.Since(start))
	}
}
