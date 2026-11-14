package main

import (
	"strings"
	"testing"
)

func TestDeriveState(t *testing.T) {
	for _, tt := range []struct {
		o    outcome
		want string
	}{
		{outcome{Skipped: true}, "-"},
		{outcome{Err: "boom"}, "error"},
		{outcome{Failure: []string{"signingCredential.untrusted"}}, "Valid"},
		{outcome{Success: []string{"signingCredential.trusted"}}, "Trusted"},
		{outcome{}, "Valid"},
		{outcome{Failure: []string{"assertion.dataHash.mismatch"}, Success: []string{"signingCredential.trusted"}}, "Invalid"},
		{outcome{Failure: []string{"signingCredential.untrusted", "claimSignature.mismatch"}}, "Invalid"},
	} {
		o := tt.o
		deriveState(&o)
		if o.State != tt.want {
			t.Errorf("%+v: state %s, want %s", tt.o, o.State, tt.want)
		}
	}
}

func TestDisagreementAndCauses(t *testing.T) {
	mk := func(seal, tool, mcp outcome) *row {
		r := &row{Item: item{Name: "x"}}
		for _, m := range modes {
			for name, o := range map[string]outcome{"C2paSeal": seal, "c2patool": tool, "c2pa-mcp": mcp} {
				deriveState(&o)
				r.Results = append(r.Results, result{Tool: name, Mode: m, Outcome: o})
			}
		}
		return r
	}
	ok := outcome{Failure: []string{"signingCredential.untrusted"}, Info: []string{"timeStamp.untrusted"}}
	rep := &report{Rows: []row{*mk(ok, ok, ok)}}
	if n := len(rep.disagreements()); n != 0 {
		t.Errorf("identical outcomes: %d disagreements", n)
	}

	// The time-stamp cause applies only to its exact pattern.
	mcp := outcome{Failure: []string{"timeStamp.untrusted", "signingCredential.untrusted"}}
	rep = &report{Rows: []row{*mk(ok, ok, mcp)}}
	ds := rep.disagreements()
	if len(ds) != 2 || ds[0].Cause == nil || rep.unexplained() != 0 {
		t.Fatalf("time-stamp pattern: %d disagreements, %d unexplained", len(ds), rep.unexplained())
	}
	odd := outcome{Failure: []string{"timeStamp.untrusted", "claimSignature.mismatch"}}
	rep = &report{Rows: []row{*mk(ok, ok, odd)}}
	if rep.unexplained() != 2 {
		t.Errorf("unknown pattern: %d unexplained, want 2", rep.unexplained())
	}
}

// TestCredentioCauses: a disagreement is explained only if every part is.
// Item paths are missing files, so only the status patterns can match.
func TestCredentioCauses(t *testing.T) {
	mk := func(seal, tool, mcp, cr outcome) *row {
		r := &row{Item: item{Name: "x", Path: "does-not-exist.jpg"}}
		for name, o := range map[string]outcome{"C2paSeal": seal, "c2patool": tool, "c2pa-mcp": mcp, "Credentio": cr} {
			deriveState(&o)
			r.Results = append(r.Results, result{Tool: name, Mode: modeTrusted, Outcome: o})
		}
		return r
	}
	ok := outcome{}
	stamp := outcome{Failure: []string{"timeStamp.untrusted"}}
	noStore := outcome{Err: "Validation failed: NOT_FOUND: No manifest store found"}
	missing := outcome{Failure: []string{"claim.missing"}}

	// Credentio alone differs, with a known pattern: explained.
	if c := explain(mk(missing, missing, missing, noStore), modeTrusted); c == nil || !strings.HasPrefix(c.Who, "Credentio") {
		t.Errorf("unsigned file: cause %+v", c)
	}
	// Credentio alone differs, unknown pattern: unexplained.
	if c := explain(mk(ok, ok, ok, outcome{Failure: []string{"claimSignature.mismatch"}}), modeTrusted); c != nil {
		t.Errorf("unknown Credentio pattern explained by %q", c.Who)
	}
	// The c2pa-mcp part is explained but Credentio's is not: unexplained.
	ok.Info = []string{"timeStamp.untrusted"}
	if c := explain(mk(ok, ok, stamp, outcome{Failure: []string{"claimSignature.mismatch"}}), modeTrusted); c != nil {
		t.Errorf("half-explained disagreement explained by %q", c.Who)
	}
	// Both parts known: the cause names both.
	if c := explain(mk(ok, ok, stamp, ok), modeTrusted); c == nil || strings.Contains(c.Who, ";") {
		t.Errorf("c2pa-mcp only: cause %+v", c)
	}
}
