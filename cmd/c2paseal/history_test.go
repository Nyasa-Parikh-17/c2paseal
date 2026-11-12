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
)

// signJSON runs sign --json and returns its result object.
func signJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	cert, key := fixture(t, "pki/leaf-chain.pem"), fixture(t, "pki/leaf.key")
	var stdout, stderr bytes.Buffer
	full := append([]string{"sign", "--json", "--cert", cert, "--key", key}, args...)
	if code := run(full, &stdout, &stderr); code != exitValid {
		t.Fatalf("run(%q): exit %d\n%s%s", full, code, stdout.String(), stderr.String())
	}
	var v map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func verifyState(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stdout bytes.Buffer
	code := run(append([]string{"verify", "--json"}, args...), &stdout, io.Discard)
	var v struct {
		State string `json:"validation_state"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatalf("verify %q: %v\n%s", args, err, stdout.String())
	}
	return code, v.State
}

// Re-signing keeps the history; --no-history replaces it.
func TestSignHistory(t *testing.T) {
	dir := t.TempDir()
	one, two, fresh := filepath.Join(dir, "one.jpg"), filepath.Join(dir, "two.jpg"), filepath.Join(dir, "fresh.jpg")
	signJSON(t, "--in", fixture(t, "unsigned/small.jpg"), "--out", one)
	if v := signJSON(t, "--in", one, "--out", two); v["manifests"] != 2.0 {
		t.Errorf("re-signed: %v manifests, want 2", v["manifests"])
	}
	if v := signJSON(t, "--in", two, "--out", fresh, "--no-history", "--source-type", "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"); v["manifests"] != 1.0 {
		t.Errorf("--no-history: %v manifests, want 1", v["manifests"])
	}
	if code, state := verifyState(t, two); code != exitValid || state != "Valid" {
		t.Errorf("verify re-signed: exit %d, state %s", code, state)
	}
	// --source-type means c2pa.created, which a signed input cannot have.
	var stdout bytes.Buffer
	cert, key := fixture(t, "pki/leaf-chain.pem"), fixture(t, "pki/leaf.key")
	code := run([]string{"sign", "--cert", cert, "--key", key, "--in", one, "--out", fresh, "--source-type", "x"}, &stdout, &stdout)
	if code != exitInvalid || !strings.Contains(stdout.String(), "NoHistory") {
		t.Errorf("--source-type on a signed input: exit %d, %s", code, stdout.String())
	}
}

// --sidecar writes <out>.c2pa, which verify and inspect find on their own.
func TestSignSidecarAndRemote(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "side.png")
	v := signJSON(t, "--in", fixture(t, "unsigned/small.png"), "--out", out, "--sidecar")
	sidecar := filepath.Join(dir, "side.c2pa")
	if v["sidecar"] != sidecar {
		t.Errorf("sidecar reported as %v, want %s", v["sidecar"], sidecar)
	}
	if code, state := verifyState(t, out); code != exitValid || state != "Valid" {
		t.Errorf("verify with sidecar: exit %d, state %s", code, state)
	}
	if code := run([]string{"inspect", out}, io.Discard, io.Discard); code != exitValid {
		t.Errorf("inspect with sidecar: exit %d", code)
	}
	// --manifest names the store explicitly.
	moved := filepath.Join(dir, "elsewhere.c2pa")
	if err := os.Rename(sidecar, moved); err != nil {
		t.Fatal(err)
	}
	if code, state := verifyState(t, out); code != exitInvalid || state != "Invalid" {
		t.Errorf("verify without sidecar: exit %d, state %s", code, state)
	}
	if code, state := verifyState(t, "--manifest", moved, out); code != exitValid || state != "Valid" {
		t.Errorf("verify --manifest: exit %d, state %s", code, state)
	}

	// Remote only: offline is inaccessible, --fetch-remote downloads it.
	store, err := os.ReadFile(moved)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(store) }))
	defer srv.Close()
	rdir := t.TempDir()
	remote := filepath.Join(rdir, "remote.png")
	v = signJSON(t, "--in", fixture(t, "unsigned/small.png"), "--out", remote, "--sidecar", "--remote", srv.URL+"/m.c2pa")
	if v["remote_url"] != srv.URL+"/m.c2pa" {
		t.Errorf("remote_url %v", v["remote_url"])
	}
	store, err = os.ReadFile(filepath.Join(rdir, "remote.c2pa"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(rdir, "remote.c2pa")); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := run([]string{"verify", remote}, &stdout, io.Discard); code != exitInvalid || !strings.Contains(stdout.String(), "manifest.inaccessible") {
		t.Errorf("verify remote offline: exit %d\n%s", code, stdout.String())
	}
	if code, state := verifyState(t, "--fetch-remote", remote); code != exitValid || state != "Valid" {
		t.Errorf("verify --fetch-remote: exit %d, state %s", code, state)
	}
}
