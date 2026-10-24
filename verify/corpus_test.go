package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// render lists statuses as "kind: code @url" in c2patool's grouping:
// success, then informational, then failure, each in log order.
func render(statuses []Status) []string {
	var out []string
	for _, k := range []Kind{Success, Informational, Failure} {
		for _, s := range statuses {
			if s.Kind() == k {
				out = append(out, fmt.Sprintf("%s: %s @%s", k, s.Code, s.URL))
			}
		}
	}
	return out
}

func renderOracle(g *fixtures.StatusGroup) []string {
	if g == nil {
		return nil
	}
	var out []string
	for _, x := range []struct {
		k    Kind
		list []fixtures.Status
	}{{Success, g.Success}, {Informational, g.Informational}, {Failure, g.Failure}} {
		for _, s := range x.list {
			out = append(out, fmt.Sprintf("%s: %s @%s", x.k, s.Code, s.URL))
		}
	}
	return out
}

// oracleDeltas renders the oracle's ingredientDeltas.
func oracleDeltas(t *testing.T, exp *fixtures.Expected) []string {
	t.Helper()
	if exp.ValidationResults == nil || len(exp.ValidationResults.IngredientDeltas) == 0 {
		return nil
	}
	var deltas []struct {
		URI    string               `json:"ingredientAssertionURI"`
		Deltas fixtures.StatusGroup `json:"validationDeltas"`
	}
	if err := json.Unmarshal(exp.ValidationResults.IngredientDeltas, &deltas); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range deltas {
		for _, line := range renderOracle(&d.Deltas) {
			out = append(out, d.URI+" | "+line)
		}
	}
	return out
}

func ourDeltas(r *Result) []string {
	var out []string
	for _, d := range r.IngredientDeltas {
		for _, line := range render(d.ValidationDeltas) {
			out = append(out, d.IngredientAssertionURI+" | "+line)
		}
	}
	return out
}

func codesOnly(lines []string) string {
	var codes []string
	for _, l := range lines {
		if _, after, ok := strings.Cut(l, ": "); ok {
			l = after
		}
		code, _, _ := strings.Cut(l, " @")
		codes = append(codes, code)
	}
	return strings.Join(codes, ", ")
}

// TestCorpus is the Phase 9 check: for every fixture and both trust modes,
// File's statuses equal c2patool's, kind by kind and in order, including
// ingredient deltas and the validation state. Where c2patool cannot read a
// file at all, File must reject it with exactly one failure status.
func TestCorpus(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	anchors := testAnchors(t)
	n := 0
	for _, f := range all {
		for _, mode := range []string{"default", "trusted"} {
			n++
			t.Run(f.String()+"/"+mode, func(t *testing.T) {
				exp, err := f.Expected()
				opts := &Options{Now: corpusTime}
				if mode == "trusted" {
					exp, err = f.Trusted()
					opts.TrustAnchors = anchors
				}
				if err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(f.Path)
				if err != nil {
					t.Fatal(err)
				}
				r := File(b, opts)
				got := render(r.ActiveManifest)

				if exp.Failed() {
					t.Logf("ROW|%s|%s|%s|(c2patool error: %s)|%v", f, mode, codesOnly(got),
						firstLine(exp.C2patoolError), len(r.ActiveManifest) == 1 && r.ActiveManifest[0].Kind() == Failure)
					if len(r.ActiveManifest) != 1 || r.ActiveManifest[0].Kind() != Failure || r.State() != Invalid {
						t.Errorf("c2patool rejects the file (%s); we gave %q, state %s", exp.C2patoolError, got, r.State())
					}
					return
				}
				want := renderOracle(exp.ValidationResults.ActiveManifest)
				gotD, wantD := ourDeltas(r), oracleDeltas(t, exp)
				ok := slices.Equal(got, want) && slices.Equal(gotD, wantD) && string(r.State()) == exp.ValidationState
				t.Logf("ROW|%s|%s|%s|%s|%v", f, mode, codesOnly(append(got, gotD...)), codesOnly(append(want, wantD...)), ok)
				if !slices.Equal(got, want) {
					t.Errorf("active manifest\n got  %q\n want %q", got, want)
				}
				if !slices.Equal(gotD, wantD) {
					t.Errorf("ingredient deltas\n got  %q\n want %q", gotD, wantD)
				}
				if string(r.State()) != exp.ValidationState {
					t.Errorf("state %s, oracle %s", r.State(), exp.ValidationState)
				}
			})
		}
	}
	if n < 40 {
		t.Errorf("only %d fixture/mode pairs", n)
	}
}

// corpusTime pins "now" for oracle comparisons to just after the corpus was
// generated (2026-10-17): after the short-lived expired.jpg signer lapsed,
// long before the test PKI's 2031 expiry. Without it the comparisons would
// start failing once the test certificates expire.
func corpusTime() time.Time { return time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC) }

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
