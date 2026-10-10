package source

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/programfeed/internal/fetch"
	"github.com/openctemio/programfeed/internal/model"
)

// testClient sends every request, whatever its host, to srv.
func testClient(srv *httptest.Server) *fetch.Client {
	return fetch.New(fetch.Options{UserAgent: fetch.UserAgent("test"), MinInterval: time.Millisecond, AllowPrivate: true,
		DialOverride: srv.Listener.Addr().String(), Timeout: 5 * time.Second})
}

func byID(ps []model.Program) map[string]model.Program {
	out := map[string]model.Program{}
	for _, p := range ps {
		out[p.ID] = p
	}
	return out
}

func TestDioDB(t *testing.T) {
	body, err := os.ReadFile("testdata/diodb.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/list.json" {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	res, err := DioDB{URL: srv.URL + "/list.json"}.Collect(context.Background(), testClient(srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Programs) != 12 || res.Skipped != 5 {
		t.Fatalf("%d programs, %d skipped", len(res.Programs), res.Skipped)
	}
	ps := byID(res.Programs)
	ada := ps["disclose:ada-health"]
	if len(ada.InScope) != 1 || ada.InScope[0].Value != "ada.com" || ada.InScope[0].Confidence != model.ConfidenceInferred || ada.ScopePublished {
		t.Errorf("ada: %+v", ada.InScope)
	}
	yt := ps["disclose:youtube"]
	if yt.Type != model.TypeBounty || yt.Platform != "self-hosted" || len(yt.InScope) != 0 || yt.Rules.SafeHarbour != model.SafeHarbourPartial {
		t.Errorf("youtube: %+v", yt)
	}
	ph := ps["disclose:platform-hosted"]
	if ph.Platform != "hackerone" || ph.Type != model.TypeBounty || len(ph.InScope) != 0 {
		t.Errorf("a security.txt on a platform host must not become a target: %+v", ph)
	}
	if len(ps["disclose:odd-path-txt"].InScope) != 0 {
		t.Error("a non-standard security.txt path must not become a target")
	}
	dead := ps["disclose:dead-link"]
	if dead.Status != model.StatusPaused || dead.Type != model.TypeBounty || dead.Contact != (model.Contact{}) ||
		dead.Rules.DisclosureDays != 90 || strings.Join(dead.Rules.Languages, ",") != "en,de" {
		t.Errorf("dead link: %+v", dead)
	}
	dups := 0
	for id := range ps {
		if strings.HasPrefix(id, "disclose:duplicate-") {
			dups++
		}
	}
	if dups != 2 {
		t.Errorf("colliding slugs must both get a hash suffix (%d)", dups)
	}
	// The public-suffix target is passed on; the collector's Normalize
	// rejects it.
	pst := ps["disclose:public-suffix-txt"]
	model.Normalize(&pst)
	if len(pst.InScope) != 0 || len(pst.Rejected) != 1 {
		t.Errorf("public suffix: %+v / %+v", pst.InScope, pst.Rejected)
	}
}

const goodTxt = `# Our policy
Contact: mailto:security@agency.gov
Contact: https://agency.gov/report
Expires: 2099-01-01T00:00:00Z
Policy: https://agency.gov/vulnerability-disclosure-policy
Preferred-Languages: en, es
Canonical: https://agency.gov/.well-known/security.txt
`

func TestParseSecurityTxt(t *testing.T) {
	f, err := ParseSecurityTxt([]byte(goodTxt))
	if err != nil || len(f.Contact) != 2 || f.Policy[0] != "https://agency.gov/vulnerability-disclosure-policy" || f.Expires.Year() != 2099 {
		t.Fatalf("%v %+v", err, f)
	}
	signed := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + strings.ReplaceAll(goodTxt, "# Our", "- # Our") +
		"-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n"
	if f, err := ParseSecurityTxt([]byte(signed)); err != nil || len(f.Policy) != 1 {
		t.Errorf("signed: %v", err)
	}
	for name, body := range map[string]string{
		"html":       "<!doctype html><html><body>Contact: x</body></html>",
		"no contact": "Policy: https://a.gov/p\n",
		"binary":     "\xff\xfe\x00",
	} {
		if _, err := ParseSecurityTxt([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSecurityTxt(t *testing.T) {
	seed := "Domain name,Domain type,Organization name,Suborganization name\n" +
		"agency.gov,Federal,Agency,Office\nnopolicy.gov,Federal,NoPolicy,\nhtml.gov,Federal,Html,\nmissing.gov,Federal,Missing,\n" +
		"down.gov,Federal,Down,\nredirect.gov,Federal,Redirect,\nexpired.gov,Federal,Expired,\nrobots.gov,Federal,Robots,\n" +
		"localhost,Federal,Bad,\n10.0.0.1,Federal,Bad,\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		if r.URL.Path == "/robots.txt" {
			if host == "robots.gov" {
				_, _ = w.Write([]byte("User-agent: *\nDisallow: /.well-known/\n"))
				return
			}
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/seed.csv" {
			_, _ = w.Write([]byte(seed))
			return
		}
		switch host {
		case "agency.gov", "robots.gov":
			_, _ = w.Write([]byte(goodTxt))
		case "nopolicy.gov":
			_, _ = w.Write([]byte("Contact: mailto:a@nopolicy.gov\n"))
		case "html.gov":
			_, _ = w.Write([]byte("<html>not found</html>"))
		case "down.gov":
			w.WriteHeader(http.StatusBadGateway)
		case "redirect.gov":
			http.Redirect(w, r, "http://other.gov/.well-known/security.txt", http.StatusFound)
		case "other.gov":
			_, _ = w.Write([]byte("Contact: mailto:a@other.gov\nPolicy: https://other.gov/p\n"))
		case "expired.gov":
			_, _ = w.Write([]byte("Contact: mailto:a@expired.gov\nExpires: 2020-01-01T00:00:00Z\nPolicy: https://expired.gov/p\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	st := SecurityTxt{SeedCSV: "http://seed.example.net/seed.csv", Scheme: "http", Workers: 3}
	res, err := st.Collect(context.Background(), testClient(srv))
	if err != nil {
		t.Fatal(err)
	}
	ps := byID(res.Programs)
	if len(ps) != 2 {
		t.Fatalf("programs: %v", keys(ps))
	}
	a := ps["securitytxt:agency.gov"]
	if a.Name != "Agency / Office (agency.gov)" || a.URL != "https://agency.gov/vulnerability-disclosure-policy" ||
		a.Contact.Email != "security@agency.gov" || a.Contact.URL != "https://agency.gov/report" || a.Terms.SHA256 == "" ||
		len(a.InScope) != 1 || a.InScope[0].Value != "agency.gov" || a.InScope[0].Confidence != model.ConfidenceInferred || a.Status != model.StatusOpen {
		t.Errorf("agency: %+v", a)
	}
	if ps["securitytxt:expired.gov"].Status != model.StatusPaused {
		t.Error("an expired security.txt must give a paused program")
	}
	// A host that did not answer is unknown (its previous record is kept);
	// a definite "no file" is not.
	if strings.Join(res.Unknown, ",") != "securitytxt:down.gov" {
		t.Errorf("unknown = %v", res.Unknown)
	}
}

func keys(m map[string]model.Program) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSlugs(t *testing.T) {
	s := UniqueSlugs([]string{"Acme Corp", "acme-corp", "Zeta", "!!!"})
	if s["Zeta"] != "zeta" || s["Acme Corp"] == s["acme-corp"] || !strings.HasPrefix(s["Acme Corp"], "acme-corp-") || s["!!!"] == "" {
		t.Errorf("%v", s)
	}
}
