package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
)

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pat, name string
		want      bool
	}{
		{"*.jpg", "a.jpg", true},
		{"*.jpg", "dir/a.jpg", false},
		{"**/*.jpg", "a.jpg", true},
		{"**/*.jpg", "x/y/a.jpg", true},
		{"photos/**", "photos/a/b.png", true},
		{"photos/**/*.png", "photos/b.png", true},
		{"photos/**/*.png", "other/b.png", false},
		{"./photos/*.png", "photos/b.png", true},
		{"p?otos/[ab].png", "photos/a.png", true},
	} {
		if got := match(tc.pat, tc.name); got != tc.want {
			t.Errorf("match(%q, %q) = %v", tc.pat, tc.name, got)
		}
	}
	for pat, root := range map[string]string{"*.jpg": ".", "a/b/**/*.png": "a/b", "/abs/*.png": "/abs", "./x/*.jpg": "./x"} {
		if got := globRoot(pat); got != root {
			t.Errorf("globRoot(%q) = %q, want %q", pat, got, root)
		}
	}
}

// workspace makes a temporary workspace with some images and makes it the
// current directory, as GITHUB_WORKSPACE is for an action.
func workspace(t *testing.T) (pki string) {
	t.Helper()
	td := signtest.TestdataDir(t)
	ws := t.TempDir()
	for _, f := range []struct{ from, to string }{
		{"unsigned/small.jpg", "photos/a.jpg"},
		{"unsigned/small.png", "photos/sub/b.png"},
		{"unsigned/small.webp", "c.webp"},
		{"unsigned/sample.heic", "photos/d.heic"},
	} {
		b, err := os.ReadFile(filepath.Join(td, f.from))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(ws, f.to)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(ws, "photos", "notes.txt"), []byte("not an image"), 0o644)
	t.Chdir(ws)
	return filepath.Join(td, "pki")
}

type fakeEnv map[string]string

func (e fakeEnv) get(k string) string { return e[k] }

func newEnv(t *testing.T, inputs map[string]string) fakeEnv {
	tmp := t.TempDir()
	e := fakeEnv{
		"RUNNER_TEMP":         tmp,
		"GITHUB_OUTPUT":       filepath.Join(tmp, "output"),
		"GITHUB_STEP_SUMMARY": filepath.Join(tmp, "summary"),
	}
	for k, v := range inputs {
		e["INPUT_"+strings.ToUpper(k)] = v
	}
	return e
}

func report(t *testing.T, e fakeEnv) []record {
	t.Helper()
	f, err := os.Open(filepath.Join(e["RUNNER_TEMP"], "c2paseal-report.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	return recs
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSignThenVerify(t *testing.T) {
	pki := workspace(t)
	var out bytes.Buffer
	e := newEnv(t, map[string]string{
		"command": "sign",
		"files":   "photos/**/*.jpg\nphotos/sub\nc.webp\nphotos/*.heic\n",
		"cert":    filepath.Join(pki, "leaf-chain.pem"),
		"key":     filepath.Join(pki, "leaf.key"),
		"title":   "release asset",
	})
	if code := run(e.get, &out); code != 0 {
		t.Fatalf("sign: exit %d\n%s", code, out.String())
	}
	recs := report(t, e)
	want := []string{"c.webp", "photos/a.jpg", "photos/d.heic", "photos/sub/b.png"}
	if len(recs) != len(want) {
		t.Fatalf("report: %+v", recs)
	}
	for i, r := range recs {
		if r.File != want[i] || r.Output != "c2paseal-signed/"+want[i] || r.Error != "" {
			t.Errorf("record %d: %+v", i, r)
		}
	}
	output := read(t, e["GITHUB_OUTPUT"])
	if !strings.Contains(output, "signed-count=4\n") || !strings.Contains(output, "c2paseal-signed/photos/sub/b.png\n") {
		t.Errorf("GITHUB_OUTPUT:\n%s", output)
	}
	if s := read(t, e["GITHUB_STEP_SUMMARY"]); !strings.Contains(s, "signed 4 of 4 files") {
		t.Errorf("summary:\n%s", s)
	}

	// Verify the signed copies: Valid without trust anchors, Trusted with.
	for _, tc := range []struct {
		trust, failOn, state string
		code                 int
	}{
		{"", "invalid", "Valid", 0},
		{"", "untrusted", "Valid", 1},
		{filepath.Join(pki, "trust-anchors.pem"), "untrusted", "Trusted", 0},
	} {
		var out bytes.Buffer
		e := newEnv(t, map[string]string{"command": "verify", "files": "c2paseal-signed", "trust": tc.trust, "fail-on": tc.failOn})
		if code := run(e.get, &out); code != tc.code {
			t.Fatalf("verify (trust %q, fail-on %s): exit %d\n%s", tc.trust, tc.failOn, code, out.String())
		}
		recs := report(t, e)
		if len(recs) != 4 {
			t.Fatalf("verify report: %+v", recs)
		}
		for _, r := range recs {
			wantFailures := 0
			if tc.state == "Valid" {
				wantFailures = 1 // signingCredential.untrusted, as c2patool reports it
			}
			if r.State != tc.state || len(r.Failures) != wantFailures {
				t.Errorf("verify %s: %+v, want %s", r.File, r, tc.state)
			}
		}
	}

	// The unsigned originals are Invalid (no manifest): exit 1 with an
	// annotation, unless fail-on is never.
	for failOn, code := range map[string]int{"invalid": 1, "never": 0} {
		var out bytes.Buffer
		e := newEnv(t, map[string]string{"command": "verify", "files": "photos/a.jpg", "fail-on": failOn})
		if got := run(e.get, &out); got != code {
			t.Errorf("unsigned, fail-on %s: exit %d\n%s", failOn, got, out.String())
		}
		if failOn == "invalid" && !strings.Contains(out.String(), "::error file=photos/a.jpg::C2PA manifest invalid: claim.missing") {
			t.Errorf("no annotation:\n%s", out.String())
		}
	}
}

func TestSignInPlaceWithPEMInputs(t *testing.T) {
	pki := workspace(t)
	var out bytes.Buffer
	e := newEnv(t, map[string]string{
		"command":  "sign",
		"files":    "photos/a.jpg",
		"cert-pem": read(t, filepath.Join(pki, "leaf-chain.pem")),
		"key-pem":  read(t, filepath.Join(pki, "leaf.key")),
		"in-place": "true",
	})
	if code := run(e.get, &out); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	signtest.CheckFile(t, "photos/a.jpg")

	// Signing again keeps the first manifest as the parent.
	out.Reset()
	e = newEnv(t, map[string]string{
		"command": "sign", "files": "photos/a.jpg", "in-place": "true",
		"cert": filepath.Join(pki, "leaf-chain.pem"), "key": "file:" + filepath.Join(pki, "leaf.key"),
	})
	if code := run(e.get, &out); code != 0 {
		t.Fatalf("re-sign: exit %d\n%s", code, out.String())
	}
	if r := report(t, e); len(r) != 1 || !r[0].Parent {
		t.Errorf("re-sign report: %+v", r)
	}
}

func TestErrors(t *testing.T) {
	pki := workspace(t)
	cert, key := filepath.Join(pki, "leaf-chain.pem"), filepath.Join(pki, "leaf.key")
	for _, tc := range []struct {
		name   string
		inputs map[string]string
		want   string
	}{
		{"bad command", map[string]string{"command": "stamp", "files": "x"}, "want sign or verify"},
		{"no files", map[string]string{"command": "verify"}, "files is empty"},
		{"missing file", map[string]string{"command": "verify", "files": "nope.jpg"}, "nope.jpg"},
		{"no match", map[string]string{"command": "verify", "files": "**/*.gif"}, "no images match"},
		{"no cert", map[string]string{"command": "sign", "files": "c.webp", "key": key}, "needs cert"},
		{"no key", map[string]string{"command": "sign", "files": "c.webp", "cert": cert}, "needs key"},
		{"both keys", map[string]string{"command": "sign", "files": "c.webp", "cert": cert, "key": key, "key-pem": "x"}, "not both"},
		{"bad fail-on", map[string]string{"command": "verify", "files": "c.webp", "fail-on": "sometimes"}, "fail-on"},
		{"bad boolean", map[string]string{"command": "sign", "files": "c.webp", "in-place": "yes"}, "in-place"},
		{"not an image", map[string]string{"command": "sign", "files": "photos/notes.txt", "cert": cert, "key": key}, "::error file=photos/notes.txt::"},
	} {
		var out bytes.Buffer
		if code := run(newEnv(t, tc.inputs).get, &out); code != 1 || !strings.Contains(out.String(), tc.want) {
			t.Errorf("%s: exit %d, output:\n%s", tc.name, code, out.String())
		}
	}
}
