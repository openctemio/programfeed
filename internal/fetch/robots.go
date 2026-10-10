package fetch

import (
	"strings"
)

// robotsRules is the group of a robots.txt that applies to the collector
// (RFC 9309): the group naming our product token, else the "*" group.
type robotsRules struct {
	disallowAll bool
	rules       []robotsRule
}

type robotsRule struct {
	allow   bool
	pattern string
}

func parseRobots(body, product string) *robotsRules {
	product = strings.ToLower(product)
	type group struct {
		agents []string
		rules  []robotsRule
	}
	var groups []*group
	var cur *group
	lastWasAgent := false
	for _, line := range strings.Split(body, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if cur == nil || !lastWasAgent {
				cur = &group{}
				groups = append(groups, cur)
			}
			cur.agents = append(cur.agents, strings.ToLower(v))
			lastWasAgent = true
		case "allow", "disallow":
			lastWasAgent = false
			if cur == nil || v == "" {
				continue
			}
			cur.rules = append(cur.rules, robotsRule{allow: k == "allow", pattern: v})
		default:
			lastWasAgent = false
		}
	}
	var mine, star []robotsRule
	matched := false
	for _, g := range groups {
		for _, a := range g.agents {
			switch {
			case a == product:
				mine = append(mine, g.rules...)
				matched = true
			case a == "*":
				star = append(star, g.rules...)
			}
		}
	}
	if matched {
		return &robotsRules{rules: mine}
	}
	return &robotsRules{rules: star}
}

// allows applies the longest matching rule; on a tie, allow wins.
func (r *robotsRules) allows(path string) bool {
	if r.disallowAll {
		return false
	}
	best, allow := -1, true
	for _, rule := range r.rules {
		if !match(rule.pattern, path) {
			continue
		}
		n := len(rule.pattern)
		if n > best || (n == best && rule.allow) {
			best, allow = n, rule.allow
		}
	}
	return allow
}

// match implements robots.txt patterns: "*" matches any run, a trailing
// "$" anchors the end, otherwise a prefix match.
func match(pattern, path string) bool {
	anchored := strings.HasSuffix(pattern, "$")
	pattern = strings.TrimSuffix(pattern, "$")
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(path, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for i, part := range parts[1:] {
		if i == len(parts)-2 && anchored {
			return len(path)-pos >= len(part) && strings.HasSuffix(path, part)
		}
		j := strings.Index(path[pos:], part)
		if j < 0 {
			return false
		}
		pos += j + len(part)
	}
	if anchored {
		return pos == len(path)
	}
	return true
}
