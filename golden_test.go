package c2paseal

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// goldenIgnore lists the oracle fields our JSON does not produce, as
// dot-separated paths ("*" matches any key). This is the only place to
// change when a field comes into or goes out of scope.
var goldenIgnore = []string{
	"validation_results", // status codes: verify package, Phase 8-9
	"validation_state",
}

func ignored(path string) bool {
	for _, pat := range goldenIgnore {
		if matchPath(strings.Split(pat, "."), strings.Split(path, ".")) {
			return true
		}
	}
	return false
}

func matchPath(pat, path []string) bool {
	if len(pat) > len(path) {
		return false
	}
	for i, p := range pat {
		if p != "*" && p != path[i] {
			return false
		}
	}
	return true
}

// diff returns the paths where got and want differ, skipping ignored paths.
func diff(path string, got, want any) []string {
	if path != "" && ignored(path) {
		return nil
	}
	join := func(k string) string {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	gm, gok := got.(map[string]any)
	wm, wok := want.(map[string]any)
	if gok && wok {
		var out []string
		keys := map[string]bool{}
		for k := range gm {
			keys[k] = true
		}
		for k := range wm {
			keys[k] = true
		}
		for _, k := range slices.Sorted(maps.Keys(keys)) {
			gv, gin := gm[k]
			wv, win := wm[k]
			switch {
			case ignored(join(k)):
			case !gin:
				out = append(out, fmt.Sprintf("%s: missing (oracle %v)", join(k), short(wv)))
			case !win:
				out = append(out, fmt.Sprintf("%s: extra (ours %v)", join(k), short(gv)))
			default:
				out = append(out, diff(join(k), gv, wv)...)
			}
		}
		return out
	}
	ga, gok := got.([]any)
	wa, wok := want.([]any)
	if gok && wok && len(ga) == len(wa) {
		var out []string
		for i := range ga {
			out = append(out, diff(join(fmt.Sprint(i)), ga[i], wa[i])...)
		}
		return out
	}
	if !reflect.DeepEqual(got, want) {
		return []string{fmt.Sprintf("%s: ours %v, oracle %v", path, short(got), short(want))}
	}
	return nil
}

func short(v any) string {
	s := fmt.Sprint(v)
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

// TestGolden compares Read's JSON with c2patool --detailed for every
// fixture c2patool can read.
func TestGolden(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range all {
		exp, err := f.Expected()
		if err != nil {
			t.Fatal(err)
		}
		if exp.Failed() {
			continue
		}
		n++
		t.Run(f.String(), func(t *testing.T) {
			s, err := Read(f.Path)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(exp.Raw, &want); err != nil {
				t.Fatal(err)
			}
			for _, d := range diff("", got, want) {
				t.Error(d)
			}
		})
	}
	if n < 13 {
		t.Errorf("only %d fixtures compared", n)
	}
}

// TestDiff guards against the golden test passing vacuously.
func TestDiff(t *testing.T) {
	want := map[string]any{"a": []any{1.0, map[string]any{"b": "x"}}, "validation_state": "Valid"}
	if d := diff("", map[string]any{"a": []any{1.0, map[string]any{"b": "x"}}}, want); len(d) != 0 {
		t.Errorf("equal values (ignoring validation_state) reported: %v", d)
	}
	for _, got := range []any{
		map[string]any{"a": []any{1.0, map[string]any{"b": "y"}}},
		map[string]any{"a": []any{1.0}},
		map[string]any{"a": []any{1.0, map[string]any{"b": "x"}}, "extra": true},
		map[string]any{},
	} {
		if len(diff("", got, want)) == 0 {
			t.Errorf("difference not reported: %v", got)
		}
	}
}

func TestSignatureTime(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	for name, wantTime := range map[string]bool{"signed/titled-ts.jpg": true, "signed/ts.png": true, "signed/small.jpg": false} {
		s, err := Read(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		r := reportSignature(s.Active.Signature)
		if (r.Time != nil) != wantTime || r.Issuer == nil || *r.CommonName != "C2paSeal Test Signer" {
			t.Errorf("%s: signature report %+v", name, r)
		}
		if got := len(s.Active.Signature.Timestamps) > 0; got != wantTime {
			t.Errorf("%s: timestamps present = %v", name, got)
		}
	}
}

func TestRFC3339(t *testing.T) {
	// Formats chrono's to_rfc3339 produces for UTC.
	for in, want := range map[string]string{
		"2026-10-17T06:25:16Z":           "2026-10-17T06:25:16+00:00",
		"2026-10-17T06:25:16.5Z":         "2026-10-17T06:25:16.500+00:00",
		"2026-10-17T06:25:16.000123Z":    "2026-10-17T06:25:16.000123+00:00",
		"2026-10-17T06:25:16.000000007Z": "2026-10-17T06:25:16.000000007+00:00",
	} {
		tm, err := time.Parse(time.RFC3339Nano, in)
		if err != nil {
			t.Fatal(err)
		}
		if got := rfc3339(tm); got != want {
			t.Errorf("rfc3339(%s) = %s, want %s", in, got, want)
		}
	}
}
