package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
		{"verify --manifest with several files", []string{"verify", "--manifest", "x.c2pa", "a.jpg", "b.jpg"}},
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

func TestSignCommand(t *testing.T) {
	cert, key := fixture(t, "pki/leaf-chain.pem"), fixture(t, "pki/leaf.key")
	out := filepath.Join(t.TempDir(), "out.jpg")
	var stdout bytes.Buffer
	args := []string{"sign", "--cert", cert, "--key", key, "--in", fixture(t, "unsigned/small.jpg"), "--out", out, "--title", "CLI test"}
	if code := run(args, &stdout, io.Discard); code != exitValid {
		t.Fatalf("sign exit %d", code)
	}
	if code := run([]string{"verify", out}, io.Discard, io.Discard); code != exitValid {
		t.Errorf("verify of CLI-signed file: exit %d", code)
	}
	if code := run([]string{"verify", "--trust", fixture(t, "pki/trust-anchors.pem"), out}, &stdout, io.Discard); code != exitValid || !strings.Contains(stdout.String(), "state: Trusted") {
		t.Errorf("verify --trust: exit %d\n%s", code, stdout.String())
	}

	usage := [][]string{
		{"sign"},
		{"sign", "--cert", cert, "--key", key, "--in", fixture(t, "unsigned/small.jpg")}, // no --out
		{"sign", "--cert", cert, "--key", cert, "--in", "a.jpg", "--out", out},           // bad key
		{"sign", "--cert", cert, "--key", key, "--in", "a.jpg", "--out", out, "extra"},
	}
	for _, a := range usage {
		if code := run(a, io.Discard, io.Discard); code != exitUsage {
			t.Errorf("run(%q) = %d, want %d", a, code, exitUsage)
		}
	}
	pngOut := filepath.Join(t.TempDir(), "out.png")
	if code := run([]string{"sign", "--cert", cert, "--key", key, "--in", fixture(t, "unsigned/small.png"), "--out", pngOut}, io.Discard, io.Discard); code != exitValid {
		t.Errorf("signing a PNG: exit %d, want %d", code, exitValid)
	}
	if code := run([]string{"verify", pngOut}, io.Discard, io.Discard); code != exitValid {
		t.Errorf("verify of CLI-signed PNG: exit %d", code)
	}
	if code := run([]string{"sign", "--cert", cert, "--key", key, "--in", cert, "--out", out}, io.Discard, io.Discard); code != exitInvalid {
		t.Errorf("signing a PEM file: exit %d, want %d", code, exitInvalid)
	}

	// A TSA that does not answer makes signing fail, with no output file.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	tsaOut := filepath.Join(t.TempDir(), "tsa.jpg")
	var stderr bytes.Buffer
	if code := run([]string{"sign", "--cert", cert, "--key", key, "--in", fixture(t, "unsigned/small.jpg"), "--out", tsaOut, "--tsa", srv.URL}, io.Discard, &stderr); code != exitInvalid || !strings.Contains(stderr.String(), "time-stamp") {
		t.Errorf("sign --tsa (404): exit %d, stderr %q; want %d and a time-stamp error", code, stderr.String(), exitInvalid)
	}
	if _, err := os.Stat(tsaOut); !os.IsNotExist(err) {
		t.Errorf("sign --tsa (404) left an output file: %v", err)
	}
}
