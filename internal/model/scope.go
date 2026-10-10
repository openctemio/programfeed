package model

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Scope caps: a CIDR wider than these is refused (a program does not own
// a /8, and a wide range in a feed would point scanners at strangers).
const (
	MinIPv4Prefix = 16
	MinIPv6Prefix = 48
)

// Ranges no program can own on the public internet (RFC 6890 and friends).
var reserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Names that never resolve on the public internet, or are reserved for
// documentation.
var reservedSuffixes = []string{"local", "localhost", "test", "example", "invalid", "internal", "onion", "arpa",
	"home.arpa", "lan", "corp", "intranet", "private", "example.com", "example.net", "example.org"}

var lookup = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(true), idna.BidiRule())

// NormalizeTarget returns the canonical form of a target value of the given
// type, or a non-empty reason it is refused.
func NormalizeTarget(typ, value string) (string, string) {
	v := strings.TrimSpace(value)
	if v == "" || len(v) > MaxValueLen || !safeText(v, MaxValueLen) {
		return "", "empty, too long or has control characters"
	}
	switch typ {
	case TargetDomain:
		return normDomain(v)
	case TargetWildcard:
		if !strings.HasPrefix(v, "*.") {
			return "", "a wildcard must start with *."
		}
		d, reason := normDomain(v[2:])
		if reason != "" {
			return "", reason
		}
		return "*." + d, ""
	case TargetIP:
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			return "", "not an IP address"
		}
		a = a.Unmap()
		if r := reservedAddr(a); r != "" {
			return "", r
		}
		return a.String(), ""
	case TargetCIDR:
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", "not a CIDR"
		}
		if p.Addr().Is4In6() {
			return "", "IPv4-mapped CIDR"
		}
		p = p.Masked()
		if (p.Addr().Is4() && p.Bits() < MinIPv4Prefix) || (p.Addr().Is6() && p.Bits() < MinIPv6Prefix) {
			return "", "CIDR wider than /" + strconv.Itoa(MinIPv4Prefix) + " (IPv4) or /" + strconv.Itoa(MinIPv6Prefix) + " (IPv6)"
		}
		for _, r := range reserved {
			if r.Overlaps(p) {
				return "", "private or reserved range"
			}
		}
		return p.String(), ""
	case TargetURL:
		return normURL(v)
	case TargetMobileApp, TargetSourceRepo, TargetOther:
		s := CleanText(v, MaxValueLen)
		if s == "" {
			return "", "empty or has control characters"
		}
		return s, ""
	}
	return "", "unknown target type"
}

func reservedAddr(a netip.Addr) string {
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return "private or reserved address"
	}
	for _, r := range reserved {
		if r.Contains(a) {
			return "private or reserved address"
		}
	}
	return ""
}

func normDomain(v string) (string, string) {
	d := strings.TrimSuffix(strings.ToLower(v), ".")
	if strings.Contains(d, "*") {
		return "", "wildcard inside a domain"
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", "an IP address, not a domain"
	}
	ascii, err := lookup.ToASCII(d)
	if err != nil {
		return "", "not a valid domain name"
	}
	if len(ascii) > 253 || !strings.Contains(ascii, ".") {
		return "", "not a fully qualified domain name"
	}
	labels := strings.Split(ascii, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", "not a valid domain name"
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", "not a valid domain name"
			}
		}
	}
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return "", "numeric top-level label"
	}
	for _, s := range reservedSuffixes {
		if ascii == s || strings.HasSuffix(ascii, "."+s) {
			return "", "reserved or non-public name"
		}
	}
	if ps, _ := publicsuffix.PublicSuffix(ascii); ps == ascii {
		return "", "a public suffix"
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(ascii); err != nil {
		return "", "a public suffix"
	}
	return ascii, ""
}

func normURL(v string) (string, string) {
	u, err := url.Parse(v)
	if err != nil {
		return "", "not a URL"
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", "not an http(s) URL"
	}
	if u.User != nil {
		return "", "credentials in URL"
	}
	host := u.Hostname()
	var h string
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if r := reservedAddr(a); r != "" || a.Zone() != "" {
			return "", "private or reserved address"
		}
		h = a.String()
		if a.Is6() {
			h = "[" + h + "]"
		}
	} else {
		d, reason := normDomain(host)
		if reason != "" {
			return "", reason
		}
		h = d
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "bad port"
		}
		h += ":" + strconv.Itoa(n)
	}
	u.Host, u.Fragment, u.RawFragment = h, "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	s := u.String()
	if len(s) > MaxValueLen {
		return "", "too long"
	}
	return s, ""
}

// PublicAddr reports whether a is a public unicast address a program could
// own (the fetcher also refuses to connect anywhere else).
func PublicAddr(a netip.Addr) bool { return reservedAddr(a.Unmap()) == "" }
