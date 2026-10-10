package model

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The published JSON Schema documents every field the feed writes, and
// nothing else.
func TestSchemaMatchesModel(t *testing.T) {
	type obj struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       map[string]obj             `json:"$defs"`
	}
	read := func(name string) obj {
		b, err := os.ReadFile("../../schema/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var o obj
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	prog, change := read("program.schema.json"), read("change.schema.json")
	cases := []struct {
		name   string
		schema obj
		v      any
	}{
		{"program", prog, Program{}},
		{"target", prog.Defs["target"], Target{}},
		{"rejected", prog.Defs["rejected"], Rejected{}},
		{"rules", prog.Defs["rules"], Rules{}},
		{"terms", prog.Defs["terms"], Terms{}},
		{"contact", prog.Defs["contact"], Contact{}},
		{"provenance", prog.Defs["provenance"], Provenance{}},
		{"change", change, Change{}},
	}
	for _, c := range cases {
		var want, got []string
		rt := reflect.TypeOf(c.v)
		for i := 0; i < rt.NumField(); i++ {
			want = append(want, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
		}
		for k := range c.schema.Properties {
			got = append(got, k)
		}
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(want, ",") != strings.Join(got, ",") {
			t.Errorf("%s: schema has %v, model has %v", c.name, got, want)
		}
	}
}
