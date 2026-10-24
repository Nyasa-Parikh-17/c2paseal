package main

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func TestRunUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"frobnicate"}},
		{"verify without file", []string{"verify"}},
		{"verify two files", []string{"verify", "a.jpg", "b.jpg"}},
		{"verify bad flag", []string{"verify", "-nope", "a.jpg"}},
		{"inspect without file", []string{"inspect"}},
		{"missing trust file", []string{"verify", "--trust", "does-not-exist.pem", "a.jpg"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args, io.Discard, io.Discard); got != exitUsage {
				t.Errorf("run(%q) = %d, want %d", tt.args, got, exitUsage)
			}
		})
	}
}

func TestVerifyExitCodes(t *testing.T) {
	trust := fixture(t, "pki/trust-anchors.pem")
	tests := []struct {
		args []string
		want int
		out  string // substring of stdout
	}{
		{[]string{"verify", fixture(t, "signed/small.jpg")}, exitValid, "state: Valid"},
		{[]string{"verify", "--trust", trust, fixture(t, "signed/small.png")}, exitValid, "state: Trusted"},
		{[]string{"verify", fixture(t, "signed/edited.jpg"), "--trust", trust}, exitValid, "ingredient.manifest.validated"},
		{[]string{"verify", fixture(t, "broken/data-flip.jpg")}, exitInvalid, "assertion.dataHash.mismatch"},
		{[]string{"verify", fixture(t, "broken/sig-flip.jpg")}, exitInvalid, "claimSignature.mismatch"},
		{[]string{"verify", fixture(t, "broken/truncated-app11.jpg")}, exitInvalid, "general.error"},
		{[]string{"verify", fixture(t, "unsigned/small.jpg")}, exitInvalid, "claim.missing"},
		{[]string{"verify", "no-such-file.jpg"}, exitInvalid, "general.error"},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		if got := run(tt.args, &out, io.Discard); got != tt.want {
			t.Errorf("run(%q) = %d, want %d\n%s", tt.args, got, tt.want, out.String())
		}
		if !strings.Contains(out.String(), tt.out) {
			t.Errorf("run(%q) output lacks %q:\n%s", tt.args, tt.out, out.String())
		}
	}
}

func TestVerifyJSON(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"verify", "--json", fixture(t, "signed/titled-ts.jpg")}, &out, io.Discard); code != exitValid {
		t.Fatalf("exit %d", code)
	}
	var v struct {
		Results struct {
			ActiveManifest []struct{ Code string } `json:"activeManifest"`
		} `json:"validation_results"`
		State string `json:"validation_state"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if v.State != "Valid" || len(v.Results.ActiveManifest) == 0 || v.Results.ActiveManifest[0].Code != "timeStamp.validated" {
		t.Errorf("unexpected JSON: %s", out.String())
	}
}

func TestInspect(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"inspect", fixture(t, "signed/small.jpg")}, &out, io.Discard); code != exitValid {
		t.Fatalf("exit %d", code)
	}
	var v struct {
		Active    string         `json:"active_manifest"`
		Manifests map[string]any `json:"manifests"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.Manifests[v.Active] == nil {
		t.Errorf("inspect output: %v\n%s", err, out.String())
	}
	if code := run([]string{"inspect", fixture(t, "unsigned/small.jpg")}, io.Discard, io.Discard); code != exitInvalid {
		t.Errorf("inspect unsigned: exit %d, want %d", code, exitInvalid)
	}
}
