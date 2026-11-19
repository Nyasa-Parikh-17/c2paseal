package c2paseal

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// TestTwoWayInterop is the images-only v1.0.0 interop check, per format,
// in both directions:
//
//   - c2patool → C2paSeal: every fixture in testdata/signed was signed by
//     c2patool. C2paSeal's validation state must equal c2patool's, with
//     default trust and with the TEST ONLY root (c2patool's states are its
//     recorded output in X.expected.json and X.trusted.expected.json).
//   - C2paSeal → c2patool: each format's unsigned fixture is signed by
//     C2paSeal, then signed again (two manifests, the first recorded as the
//     parent ingredient). c2patool, run now, must report Valid with default
//     trust and Trusted with the TEST ONLY root.
//
// The matrix is logged (go test -v -run TestTwoWayInterop). The second
// direction needs c2patool on PATH; with C2PASEAL_REQUIRE_C2PATOOL=1 its
// absence is a failure, as in CI.
func TestTwoWayInterop(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	anchorsPath := filepath.Join(dir, "pki", "trust-anchors.pem")
	anchors, err := LoadTrustAnchors(anchorsPath)
	if err != nil {
		t.Fatal(err)
	}
	formats := []string{FormatJPEG, FormatPNG, FormatWebP, FormatHEIC, FormatAVIF}
	type cell struct{ files, agree int }
	fromTool := map[string]*cell{}
	for _, f := range formats {
		fromTool[f] = &cell{}
	}

	// c2patool → C2paSeal.
	signed, _ := filepath.Glob(filepath.Join(dir, "signed", "*"))
	sort.Strings(signed)
	for _, path := range signed {
		if strings.HasSuffix(path, ".json") {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		format := DetectFormat(b)
		c, ok := fromTool[format]
		if !ok {
			t.Errorf("%s: unexpected format %q", path, format)
			continue
		}
		c.files++
		agree := true
		for _, mode := range []struct {
			oracle string
			opts   *VerifyOptions
		}{
			{path + ".expected.json", nil},
			{path + ".trusted.expected.json", &VerifyOptions{TrustAnchors: anchors}},
		} {
			want := oracleState(t, mode.oracle)
			got := string(VerifyBytes(b, mode.opts).State())
			if got != want {
				agree = false
				t.Errorf("c2patool → C2paSeal: %s (%s): C2paSeal %s, c2patool %s", filepath.Base(path), filepath.Base(mode.oracle), got, want)
			}
		}
		if agree {
			c.agree++
		}
	}

	// C2paSeal → c2patool.
	c2patool, err := exec.LookPath("c2patool")
	if err != nil {
		if os.Getenv("C2PASEAL_REQUIRE_C2PATOOL") == "1" {
			t.Fatal("c2patool not on PATH")
		}
		t.Log("c2patool not on PATH: skipping C2paSeal → c2patool")
	}
	chain, key, err := LoadSigner(filepath.Join(dir, "pki", "leaf-chain.pem"), filepath.Join(dir, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned := map[string]string{FormatJPEG: "small.jpg", FormatPNG: "small.png", FormatWebP: "small.webp", FormatHEIC: "sample.heic", FormatAVIF: "sample.avif"}
	toTool := map[string]string{}
	tmp := t.TempDir()
	for _, f := range formats {
		if c2patool == "" {
			toTool[f] = "not run"
			continue
		}
		in, err := os.ReadFile(filepath.Join(dir, "unsigned", unsigned[f]))
		if err != nil {
			t.Fatal(err)
		}
		once, err := SignBytes(in, &SignOptions{Chain: chain, Signer: key})
		if err != nil {
			t.Fatal(err)
		}
		twice, err := SignBytes(once, &SignOptions{Chain: chain, Signer: key})
		if err != nil {
			t.Fatal(err)
		}
		results := []string{}
		for _, v := range []struct {
			name string
			b    []byte
		}{{"signed", once}, {"re-signed", twice}} {
			path := filepath.Join(tmp, v.name+"-"+unsigned[f])
			if err := os.WriteFile(path, v.b, 0o644); err != nil {
				t.Fatal(err)
			}
			def := c2patoolState(t, c2patool, path)
			tr := c2patoolState(t, c2patool, path, "trust", "--trust_anchors", relSlash(t, anchorsPath))
			if def != string(verify.Valid) || tr != string(verify.Trusted) {
				t.Errorf("C2paSeal → c2patool: %s %s: c2patool %s / %s, want Valid / Trusted", v.name, unsigned[f], def, tr)
			}
			results = append(results, fmt.Sprintf("%s %s/%s", v.name, def, tr))
		}
		toTool[f] = strings.Join(results, ", ")
	}

	var report strings.Builder
	report.WriteString("\n| Format | c2patool → C2paSeal (same verdict, both trust modes) | C2paSeal → c2patool (default / trusted) |\n|---|---|---|\n")
	for _, f := range formats {
		fmt.Fprintf(&report, "| %s | %d of %d files | %s |\n", f, fromTool[f].agree, fromTool[f].files, toTool[f])
		if fromTool[f].files == 0 {
			t.Errorf("%s: no c2patool-signed fixture", f)
		}
	}
	t.Log(report.String())
}

// oracleState is the validation_state recorded in a c2patool output file.
func oracleState(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		State string `json:"validation_state"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out.State
}

// c2patoolState runs c2patool on path and returns its validation_state.
func c2patoolState(t *testing.T, c2patool, path string, extra ...string) string {
	t.Helper()
	out, err := exec.Command(c2patool, append([]string{relSlash(t, path)}, extra...)...).Output()
	if err != nil {
		t.Fatalf("c2patool %s: %v", path, err)
	}
	var r struct {
		State string `json:"validation_state"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("c2patool %s: %v\n%s", path, err, out)
	}
	return r.State
}

// relSlash makes path relative to the working directory, with forward
// slashes: c2patool reads an absolute Windows path (C:/...) as a URL.
func relSlash(t *testing.T, path string) string {
	t.Helper()
	wd, _ := os.Getwd()
	r, err := filepath.Rel(wd, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(r)
}
