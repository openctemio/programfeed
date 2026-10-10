package main

import (
	"testing"

	"github.com/openctemio/programfeed/policy"
)

func names(t *testing.T, list string, only []string, local bool) []string {
	t.Helper()
	srcs, err := sources(list, "", only, local)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range srcs {
		out = append(out, s.Meta().Name)
	}
	return out
}

// A signed build does not even fetch dataset platforms the policy does not
// publish; a local-only build reads everything.
func TestSourceSelectionFollowsPolicy(t *testing.T) {
	pub := policy.Default().PublishablePlatforms()
	if got := names(t, "bounty-targets,pd-bounty,diodb", pub, false); len(got) != 2 || got[0] != "pd-bounty" || got[1] != "disclose" {
		t.Errorf("signed build: %v (bounty-targets has no publishable platform and must not be fetched)", got)
	}
	if got := names(t, "bounty-targets,pd-bounty", pub, true); len(got) != 2 || got[0] != "bounty-targets" {
		t.Errorf("local-only build: %v", got)
	}
	if got := names(t, "bounty-targets", pub, false); got != nil {
		t.Errorf("nothing to fetch must be an error, got %v", got)
	}
}
