package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

const td = "../../testdata"

func readFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(td, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testSigner(t *testing.T) signOptions {
	return signOptions{Cert: string(readFile(t, "pki/leaf-chain.pem")), Key: string(readFile(t, "pki/leaf.key"))}
}

// TestVerifyJSON checks verify() against the oracle's validation state for
// the signed fixtures, in both trust modes, and its JSON shape against the
// CLI's `verify --json`.
func TestVerifyJSON(t *testing.T) {
	anchors := string(readFile(t, "pki/trust-anchors.pem"))
	files, _ := filepath.Glob(filepath.Join(td, "signed", "*.*"))
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, ".json") {
			continue
		}
		n++
		rel, _ := filepath.Rel(td, f)
		b := readFile(t, rel)
		for _, mode := range []struct{ suffix, anchors string }{{".expected.json", ""}, {".trusted.expected.json", anchors}} {
			t.Run(filepath.Base(f)+mode.suffix, func(t *testing.T) {
				var oracle struct {
					State verify.State `json:"validation_state"`
				}
				if err := json.Unmarshal(readFile(t, rel+mode.suffix), &oracle); err != nil {
					t.Fatal(err)
				}
				out := verifyJSON(b, verifyOptions{TrustAnchors: mode.anchors})
				var got map[string]json.RawMessage
				if err := json.Unmarshal(out, &got); err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || got["validation_results"] == nil || got["validation_state"] == nil {
					t.Fatalf("keys = %v, want validation_results and validation_state", keys(got))
				}
				var state verify.State
				json.Unmarshal(got["validation_state"], &state)
				if state != oracle.State {
					t.Errorf("validation_state = %s, oracle %s", state, oracle.State)
				}
				// Same JSON as the CLI's verify --json (which indents it).
				opts := &c2paseal.VerifyOptions{}
				if mode.anchors != "" {
					opts.TrustAnchors, _ = c2paseal.ParseTrustAnchors([]byte(mode.anchors))
				}
				r := c2paseal.VerifyBytes(b, opts)
				cli, _ := json.Marshal(struct {
					Results *verify.Result `json:"validation_results"`
					State   verify.State   `json:"validation_state"`
				}{r, r.State()})
				if string(cli) != string(out) {
					t.Errorf("verify() JSON differs from the CLI's:\n got %s\nwant %s", out, cli)
				}
			})
		}
	}
	if n == 0 {
		t.Fatal("no signed fixtures")
	}
}

func TestVerifyJSONErrors(t *testing.T) {
	b := readFile(t, "signed/small.jpg")
	for _, tc := range []struct {
		name string
		o    verifyOptions
		want string
	}{
		{"bad anchors", verifyOptions{TrustAnchors: "not PEM"}, "trustAnchors: "},
		{"bad allowed list", verifyOptions{AllowedList: "nothing here"}, "allowedList: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := errorOf(t, verifyJSON(b, tc.o)); !strings.HasPrefix(e, tc.want) {
				t.Errorf("error = %q, want prefix %q", e, tc.want)
			}
		})
	}
	// Malformed files are results, not errors.
	for _, in := range [][]byte{nil, []byte("not an image"), readFile(t, "broken/truncated-app11.jpg")} {
		var got verifyResult
		if err := json.Unmarshal(verifyJSON(in, verifyOptions{}), &got); err != nil {
			t.Fatal(err)
		}
		if got.State != verify.Invalid {
			t.Errorf("%.20q: state %s, want Invalid", in, got.State)
		}
	}
}

func TestSignJSON(t *testing.T) {
	anchors, err := c2paseal.ParseTrustAnchors(readFile(t, "pki/trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file, format string
		manifests    int
	}{
		{"unsigned/small.jpg", "jpeg", 1},
		{"unsigned/small.png", "png", 1},
		{"signed/small.jpg", "jpeg", 2}, // keeps the history
	} {
		t.Run(tc.file, func(t *testing.T) {
			o := testSigner(t)
			o.Title = "wasm test"
			out := signJSON(readFile(t, tc.file), o)
			var got signResult
			if err := json.Unmarshal(out, &got); err != nil || got.Data == nil {
				t.Fatalf("sign() = %.200s (%v)", out, err)
			}
			if got.Format != tc.format || got.Manifests != tc.manifests || !strings.HasPrefix(got.ActiveManifest, "urn:c2pa:") || got.TimeStamped || got.OCSPStapled {
				t.Errorf("sign() = %+v", got)
			}
			if s := c2paseal.VerifyBytes(got.Data, &c2paseal.VerifyOptions{TrustAnchors: anchors}).State(); s != verify.Trusted {
				t.Errorf("signed file verifies %s, want Trusted", s)
			}
		})
	}
	o := testSigner(t)
	for _, tc := range []struct {
		name string
		in   []byte
		o    signOptions
		want string
	}{
		{"no key", readFile(t, "unsigned/small.jpg"), signOptions{Cert: o.Cert}, "sign: cert and key are required"},
		{"bad cert", readFile(t, "unsigned/small.jpg"), signOptions{Cert: "x", Key: o.Key}, "c2paseal: certificate: no PEM certificates"},
		{"not an image", []byte("hello"), o, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := errorOf(t, signJSON(tc.in, tc.o)); !strings.HasPrefix(e, tc.want) {
				t.Errorf("error = %q, want prefix %q", e, tc.want)
			}
		})
	}
}

func TestVersionJSON(t *testing.T) {
	var v map[string]string
	if err := json.Unmarshal(versionJSON(), &v); err != nil || v["version"] == "" || len(v) != 2 {
		t.Errorf("version() = %v (%v)", v, err)
	}
}

// errorOf returns the "error" of an error result, failing if there is none.
func errorOf(t *testing.T, out []byte) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &e); err != nil || e.Error == "" {
		t.Fatalf("want an error result, got %.200s", out)
	}
	return e.Error
}

func keys(m map[string]json.RawMessage) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	return k
}
