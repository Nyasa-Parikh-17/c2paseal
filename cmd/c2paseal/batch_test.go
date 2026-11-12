package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// jsonLines splits JSON Lines output into objects.
func jsonLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 64<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line is not JSON: %v\n%s", err, sc.Bytes())
		}
		out = append(out, m)
	}
	return out
}

func runCLI(args ...string) (int, []byte, []byte) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.Bytes(), stderr.Bytes()
}

// TestBatchMatchesSingle is the Phase 19 check: a recursive batch run over
// testdata/ gives, for every image, exactly what verifying (and inspecting)
// that file alone gives, and the exit code is 1 because some are invalid.
func TestBatchMatchesSingle(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(dir, "pki", "trust-anchors.pem")
	for _, mode := range [][]string{nil, {"--trust", trust}} {
		args := append([]string{"verify", "--json", "--recursive"}, mode...)
		code, out, _ := runCLI(append(args, dir)...)
		if code != exitInvalid {
			t.Errorf("batch exit %d, want %d (the corpus has invalid files)", code, exitInvalid)
		}
		lines := jsonLines(t, out)
		all, err := fixtures.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) < len(all) {
			t.Errorf("%d results for %d fixtures", len(lines), len(all))
		}
		var files []string
		for _, l := range lines {
			file, _ := l["file"].(string)
			files = append(files, file)
			delete(l, "file")
			args := append([]string{"verify", "--json"}, mode...)
			code, single, _ := runCLI(append(args, file)...)
			var want map[string]any
			if err := json.Unmarshal(single, &want); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if !reflect.DeepEqual(l, want) {
				t.Errorf("%s: batch result differs from single-file result\n batch  %v\n single %v", file, l, want)
			}
			if (code == exitInvalid) != (want["validation_state"] == "Invalid") {
				t.Errorf("%s: single exit %d, state %v", file, code, want["validation_state"])
			}
		}
		if !slices.IsSorted(files) {
			t.Error("batch files not in sorted order")
		}
	}

	// inspect: each line is the single-file store, or the same error.
	code, out, _ := runCLI("inspect", "--recursive", filepath.Join(dir, "legacy"), filepath.Join(dir, "signed"))
	if code != exitInvalid { // legacy/prerelease.jpg has no readable store
		t.Errorf("inspect batch exit %d", code)
	}
	for _, l := range jsonLines(t, out) {
		file := l["file"].(string)
		_, single, _ := runCLI("inspect", file)
		var want map[string]any
		if err := json.Unmarshal(single, &want); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		got := l["manifest_store"]
		if e, ok := l["error"]; ok {
			got = map[string]any{"error": e}
		}
		if !reflect.DeepEqual(got, any(want)) {
			t.Errorf("%s: inspect batch differs from single", file)
		}
	}
}

func TestExpand(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.jpg", "a.PNG", "notes.txt", "c.jpeg", "sub/d.jpg", "sub/deeper/e.png", "x.jpg.expected.json"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names := func(es []entry) []string {
		var out []string
		for _, e := range es {
			rel, _ := filepath.Rel(dir, e.path)
			if e.err != nil {
				rel += " (error)"
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return out
	}
	if got, want := names(expand([]string{dir}, false)), []string{"a.PNG", "b.jpg", "c.jpeg"}; !slices.Equal(got, want) {
		t.Errorf("flat: %q, want %q", got, want)
	}
	if got, want := names(expand([]string{dir}, true)), []string{"a.PNG", "b.jpg", "c.jpeg", "sub/d.jpg", "sub/deeper/e.png"}; !slices.Equal(got, want) {
		t.Errorf("recursive: %q, want %q", got, want)
	}
	// Files given by name are kept as given, even without an image extension.
	missing := filepath.Join(dir, "missing.jpg")
	got := names(expand([]string{filepath.Join(dir, "notes.txt"), missing, filepath.Join(dir, "sub")}, false))
	if want := []string{"notes.txt", "missing.jpg (error)", "sub/d.jpg"}; !slices.Equal(got, want) {
		t.Errorf("mixed: %q, want %q", got, want)
	}
	if batchMode([]string{filepath.Join(dir, "b.jpg")}) || !batchMode([]string{dir}) || !batchMode([]string{"a", "b"}) {
		t.Error("batchMode")
	}
}

func TestVerifyBatchText(t *testing.T) {
	signed := fixture(t, "signed/small.jpg")
	unsigned := fixture(t, "unsigned/small.jpg")
	code, out, _ := runCLI("verify", signed, unsigned, "does-not-exist.jpg")
	if code != exitInvalid {
		t.Errorf("exit %d, want %d", code, exitInvalid)
	}
	text := string(out)
	for _, want := range []string{
		signed + ": Valid\n  failure signingCredential.untrusted\n",
		unsigned + ": Invalid\n  failure claim.missing\n",
		"does-not-exist.jpg: error: ",
		"3 files: 0 Trusted, 1 Valid, 1 Invalid, 1 unreadable\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	// All valid: exit 0.
	if code, _, _ := runCLI("verify", "--json", signed, fixture(t, "signed/small.png")); code != exitValid {
		t.Errorf("two valid files: exit %d", code)
	}
	// Errors as JSON lines.
	_, out, _ = runCLI("verify", "--json", signed, "does-not-exist.jpg")
	lines := jsonLines(t, out)
	if len(lines) != 2 || lines[1]["error"] == nil || lines[0]["validation_state"] != "Valid" {
		t.Errorf("JSON lines: %v", lines)
	}
}
