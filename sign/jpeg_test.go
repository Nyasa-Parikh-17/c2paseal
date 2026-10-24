package sign

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// anchors returns the TEST ONLY root as a trust anchor.
func anchors(t *testing.T) []*x509.Certificate {
	t.Helper()
	dir, _ := fixtures.Dir()
	b, err := os.ReadFile(filepath.Join(dir, "pki", "root.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{c}
}

// unsignedJPEGs returns the unsigned JPEG fixtures.
func unsignedJPEGs(t *testing.T) []fixtures.Fixture {
	t.Helper()
	fs, err := fixtures.ListKind(fixtures.Unsigned)
	if err != nil {
		t.Fatal(err)
	}
	fs = slices.DeleteFunc(fs, func(f fixtures.Fixture) bool { return f.Format != "jpeg" })
	if len(fs) < 3 {
		t.Fatalf("only %d unsigned JPEG fixtures", len(fs))
	}
	return fs
}

// failures returns the failure codes in a result.
func failures(r *verify.Result) []string {
	var out []string
	for _, s := range r.Statuses() {
		if s.Kind() == verify.Failure {
			out = append(out, s.Code)
		}
	}
	return out
}

func has(r *verify.Result, code string) bool {
	return slices.ContainsFunc(r.ActiveManifest, func(s verify.Status) bool { return s.Code == code })
}

// checkSigned asserts our verifier finds no integrity failures: only
// signingCredential.untrusted without anchors, nothing with them.
func checkSigned(t *testing.T, name string, signed []byte) {
	t.Helper()
	r := verify.File(signed, nil)
	if got := failures(r); !slices.Equal(got, []string{verify.SigningCredentialUntrusted}) || r.State() != verify.Valid {
		t.Errorf("%s: failures %q, state %s; want only untrusted, Valid\n%+v", name, got, r.State(), r.ActiveManifest)
	}
	for _, code := range []string{verify.ClaimSignatureValidated, verify.ClaimSignatureInsideValidity, verify.AssertionDataHashMatch} {
		if !has(r, code) {
			t.Errorf("%s: no %s", name, code)
		}
	}
	tr := verify.File(signed, &verify.Options{TrustAnchors: anchors(t)})
	if got := failures(tr); len(got) != 0 || tr.State() != verify.Trusted {
		t.Errorf("%s with test root trusted: failures %q, state %s", name, got, tr.State())
	}
}

// Done-when (1): every unsigned JPEG fixture, signed by us, verifies with no
// integrity failures.
func TestSignFixtures(t *testing.T) {
	chain, key := testPKI(t)
	for _, f := range unsignedJPEGs(t) {
		t.Run(f.Name, func(t *testing.T) {
			in, err := os.ReadFile(f.Path)
			if err != nil {
				t.Fatal(err)
			}
			orig := bytes.Clone(in)
			out, err := JPEG(in, &Options{Chain: chain, Signer: key, Title: f.Name})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(in, orig) {
				t.Fatal("input was modified")
			}
			checkSigned(t, f.Name, out)
			if stripped, err := jpeg.Strip(out); err != nil || !bytes.Equal(stripped, in) {
				t.Errorf("Strip(signed) != original (%v): signing changed image bytes", err)
			}
		})
	}
}

// TestResign replaces a c2patool manifest with ours.
func TestResign(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "signed", "edited.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := JPEG(in, &Options{Chain: chain, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, "edited.jpg re-signed", out)
	st, err := jpeg.Extract(out)
	if err != nil || len(st.Root.Contents()) != 1 {
		t.Errorf("re-signed store should hold exactly our manifest (%v)", err)
	}
}

// TestMultiSegment uses a big thumbnail so the store spans several APP11
// segments and the in-place writes cross segment boundaries.
func TestMultiSegment(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "unsigned", "small.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{0xAB}, 3*jpeg.MaxChunk)
	out, err := JPEG(in, &Options{Chain: chain, Signer: key, Thumbnail: &assertion.Thumbnail{Format: "image/jpeg", Data: big}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := jpeg.Extract(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Segments) < 4 {
		t.Errorf("%d APP11 segments, want at least 4", len(st.Segments))
	}
	checkSigned(t, "multi-segment", out)
}

func TestTamper(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "unsigned", "small.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := JPEG(in, &Options{Chain: chain, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	st, err := jpeg.Extract(out)
	if err != nil {
		t.Fatal(err)
	}

	image := bytes.Clone(out)
	image[len(image)-10] ^= 0x01 // inside the scan data, outside the exclusion
	if r := verify.File(image, nil); !slices.Contains(failures(r), verify.AssertionDataHashMismatch) {
		t.Errorf("image change not detected: %q", failures(r))
	}

	sig := bytes.Clone(out)
	last := st.Segments[len(st.Segments)-1]
	sig[last.End()-1] ^= 0x01 // last byte of the store: the signature
	if r := verify.File(sig, nil); !slices.Contains(failures(r), verify.ClaimSignatureMismatch) {
		t.Errorf("signature change not detected: %q", failures(r))
	}
}

// Done-when (3): a deliberately mis-sized placeholder is caught by the
// production length checks and nothing is returned.
func TestMisSizedPlaceholder(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "unsigned", "small.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{63, 65, 0} {
		out, err := signJPEG(in, &Options{Chain: chain, Signer: key}, buildConfig{sigLen: n})
		if !errors.Is(err, ErrSizeMismatch) || out != nil {
			t.Errorf("signature placeholder of %d bytes: err %v, output %d bytes; want ErrSizeMismatch, none", n, err, len(out))
		}
	}
	// Step 7's final check on its own.
	if err := checkReserved(1000, 1001); !errors.Is(err, ErrSizeMismatch) {
		t.Errorf("checkReserved(1000, 1001) = %v", err)
	}
	if err := checkReserved(1000, 1000); err != nil {
		t.Errorf("checkReserved(1000, 1000) = %v", err)
	}
}

func TestSignErrors(t *testing.T) {
	chain, key := testPKI(t)
	opts := &Options{Chain: chain, Signer: key}
	for name, in := range map[string][]byte{
		"empty":     nil,
		"PNG":       []byte("\x89PNG\r\n\x1a\n"),
		"truncated": {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x01},
	} {
		if out, err := JPEG(in, opts); err == nil || out != nil {
			t.Errorf("%s: signed anyway", name)
		}
	}
	if _, err := JPEG([]byte{0xFF, 0xD8}, &Options{}); !errors.Is(err, ErrNoSigner) {
		t.Errorf("no signer: %v", err)
	}
}

// Done-when (2): c2patool reports no integrity failures on our output.
// Skipped where c2patool is not installed.
func TestC2patool(t *testing.T) {
	if _, err := exec.LookPath("c2patool"); err != nil {
		t.Skip("c2patool not on PATH")
	}
	settings := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(settings, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("C2PATOOL_SETTINGS", settings)
	chain, key := testPKI(t)
	for _, f := range unsignedJPEGs(t) {
		in, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		out, err := JPEG(in, &Options{Chain: chain, Signer: key})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), f.Name)
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []struct {
			args      []string
			state     string
			failCodes []string
		}{
			{nil, "Valid", []string{verify.SigningCredentialUntrusted}},
			// c2patool reads "C:/..." as a URL, so pass the anchors relatively.
			{[]string{"trust", "--trust_anchors", "../testdata/pki/trust-anchors.pem"}, "Trusted", nil},
		} {
			cmd := exec.Command("c2patool", append([]string{path, "--detailed"}, mode.args...)...)
			b, err := cmd.Output()
			if err != nil {
				t.Fatalf("%s: c2patool: %v", f.Name, err)
			}
			var rep struct {
				State   string `json:"validation_state"`
				Results struct {
					Active struct {
						Failure []struct{ Code string } `json:"failure"`
					} `json:"activeManifest"`
				} `json:"validation_results"`
			}
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatalf("%s: c2patool output: %v", f.Name, err)
			}
			var codes []string
			for _, x := range rep.Results.Active.Failure {
				codes = append(codes, x.Code)
			}
			if rep.State != mode.state || !slices.Equal(codes, mode.failCodes) {
				t.Errorf("%s %v: c2patool state %s, failures %q; want %s, %q", f.Name, mode.args, rep.State, codes, mode.state, mode.failCodes)
			}
		}
	}
}
