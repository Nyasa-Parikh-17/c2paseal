package sign

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// unsignedPNGs returns the unsigned PNG fixtures.
func unsignedPNGs(t *testing.T) []fixtures.Fixture {
	t.Helper()
	fs, err := fixtures.ListKind(fixtures.Unsigned)
	if err != nil {
		t.Fatal(err)
	}
	fs = slices.DeleteFunc(fs, func(f fixtures.Fixture) bool { return f.Format != "png" })
	if len(fs) < 2 {
		t.Fatalf("only %d unsigned PNG fixtures", len(fs))
	}
	return fs
}

// cabx returns the signed PNG's caBX chunk, failing on a bad CRC.
func cabx(t *testing.T, signed []byte) png.Chunk {
	t.Helper()
	st, err := png.Extract(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Chunk.CRCValid {
		t.Fatal("caBX chunk CRC is wrong")
	}
	return st.Chunk
}

// Every unsigned PNG fixture, signed by us, verifies with no integrity
// failures; the exclusion is exactly the caBX chunk and Strip gives the
// input back.
func TestSignPNGFixtures(t *testing.T) {
	chain, key := testPKI(t)
	for _, f := range unsignedPNGs(t) {
		t.Run(f.Name, func(t *testing.T) {
			in := readFixture(t, f)
			orig := bytes.Clone(in)
			out, err := PNG(in, &Options{Chain: chain, Signer: key, Title: f.Name})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(in, orig) {
				t.Fatal("input was modified")
			}
			checkSigned(t, f.Name, out)
			c := cabx(t, out)
			if c.Offset != len(png.Signature)+25 { // straight after IHDR
				t.Errorf("caBX at %d, want right after IHDR", c.Offset)
			}
			if stripped, err := png.Strip(out); err != nil || !bytes.Equal(stripped, in) {
				t.Errorf("Strip(signed) != original (%v): signing changed image bytes", err)
			}
		})
	}
}

// TestResignPNG replaces a c2patool manifest (with a time-stamp and a
// thumbnail) with ours (NoHistory).
func TestResignPNG(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "signed", "ts.png"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := PNG(in, &Options{Chain: chain, Signer: key, NoHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, "ts.png re-signed", out)
	st, err := png.Extract(out)
	if err != nil || len(st.Root.Contents()) != 1 {
		t.Errorf("re-signed store should hold exactly our manifest (%v)", err)
	}
}

// TestPNGThumbnailAndTimestamp: a large store (thumbnail) plus a time-stamp
// in one chunk.
func TestPNGThumbnailAndTimestamp(t *testing.T) {
	chain, key := testPKI(t)
	tsa, srv := newFakeTSA(t)
	tsa.At = func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }
	in := readFixture(t, unsignedPNGs(t)[0])
	thumb := &assertion.Thumbnail{Format: "image/png", Data: bytes.Repeat([]byte{0xCD}, 200_000)}
	out, err := PNG(in, &Options{Chain: chain, Signer: key, Thumbnail: thumb, TSAURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, "thumbnail + time-stamp", out)
	afterExpiry := func() time.Time { return chain[0].NotAfter.AddDate(1, 0, 0) }
	r := verify.File(out, &verify.Options{TrustAnchors: anchors(t), Now: afterExpiry})
	if got := failures(r); len(got) != 0 || !has(r, verify.TimeStampTrusted) {
		t.Errorf("after signer expiry: failures %q, statuses %q", got, statusCodes(r))
	}
}

func TestTamperPNG(t *testing.T) {
	chain, key := testPKI(t)
	in := readFixture(t, unsignedPNGs(t)[0])
	out, err := PNG(in, &Options{Chain: chain, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	c := cabx(t, out)

	// Flip a byte in the IDAT data (after caBX) and fix that chunk's CRC,
	// so only the hard binding can notice.
	image := bytes.Clone(out)
	idat := c.End()
	n := int(binary.BigEndian.Uint32(image[idat:]))
	image[idat+8] ^= 0x01
	binary.BigEndian.PutUint32(image[idat+8+n:], crc32.ChecksumIEEE(image[idat+4:idat+8+n]))
	if r := verify.File(image, nil); !slices.Contains(failures(r), verify.AssertionDataHashMismatch) {
		t.Errorf("image change not detected: %q", failures(r))
	}

	sig := bytes.Clone(out)
	sig[c.End()-5] ^= 0x01 // last store byte (before the CRC): the signature
	if r := verify.File(sig, nil); !slices.Contains(failures(r), verify.ClaimSignatureMismatch) {
		t.Errorf("signature change not detected: %q", failures(r))
	}
}

// A mis-sized placeholder is caught for PNG too, with no output.
func TestMisSizedPlaceholderPNG(t *testing.T) {
	chain, key := testPKI(t)
	in := readFixture(t, unsignedPNGs(t)[0])
	for _, n := range []int{63, 65, 0} {
		out, err := embed(in, &Options{Chain: chain, Signer: key}, buildConfig{sigLen: n}, &pngContainer{})
		if !errors.Is(err, ErrSizeMismatch) || out != nil {
			t.Errorf("signature placeholder of %d bytes: err %v, output %v; want ErrSizeMismatch, none", n, err, out != nil)
		}
	}
}

func TestSignPNGErrors(t *testing.T) {
	chain, key := testPKI(t)
	opts := &Options{Chain: chain, Signer: key}
	sig := []byte(png.Signature)
	for name, in := range map[string][]byte{
		"empty":     nil,
		"JPEG":      {0xFF, 0xD8, 0xFF, 0xD9},
		"no IHDR":   append(bytes.Clone(sig), 0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82),
		"truncated": append(bytes.Clone(sig), 0, 0, 0, 13, 'I', 'H'),
	} {
		if out, err := PNG(in, opts); err == nil || out != nil {
			t.Errorf("%s: signed anyway", name)
		}
	}
}

// c2patool reports no integrity failures on our signed PNGs, with and
// without a time-stamp. Skipped where c2patool is not installed.
func TestC2patoolPNG(t *testing.T) {
	if _, err := exec.LookPath("c2patool"); err != nil {
		t.Skip("c2patool not on PATH")
	}
	settings := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(settings, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("C2PATOOL_SETTINGS", settings)
	chain, key := testPKI(t)
	_, srv := newFakeTSA(t)
	for _, f := range unsignedPNGs(t) {
		for _, tsaURL := range []string{"", srv.URL} {
			out, err := PNG(readFixture(t, f), &Options{Chain: chain, Signer: key, TSAURL: tsaURL})
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
				{[]string{"trust", "--trust_anchors", "../testdata/pki/trust-anchors.pem"}, "Trusted", nil},
			} {
				b, err := exec.Command("c2patool", append([]string{path, "--detailed"}, mode.args...)...).Output()
				if err != nil {
					t.Fatalf("%s: c2patool: %v", f.Name, err)
				}
				var rep struct {
					State   string `json:"validation_state"`
					Results struct {
						Active struct {
							Success []struct{ Code string } `json:"success"`
							Failure []struct{ Code string } `json:"failure"`
						} `json:"activeManifest"`
					} `json:"validation_results"`
				}
				if err := json.Unmarshal(b, &rep); err != nil {
					t.Fatalf("%s: c2patool output: %v", f.Name, err)
				}
				var fail, ok []string
				for _, x := range rep.Results.Active.Failure {
					fail = append(fail, x.Code)
				}
				for _, x := range rep.Results.Active.Success {
					ok = append(ok, x.Code)
				}
				if rep.State != mode.state || !slices.Equal(fail, mode.failCodes) {
					t.Errorf("%s tsa=%v %v: c2patool state %s, failures %q; want %s, %q", f.Name, tsaURL != "", mode.args, rep.State, fail, mode.state, mode.failCodes)
				}
				if !slices.Contains(ok, verify.AssertionDataHashMatch) || (tsaURL != "" && !slices.Contains(ok, verify.TimeStampValidated)) {
					t.Errorf("%s tsa=%v %v: c2patool success codes %q", f.Name, tsaURL != "", mode.args, ok)
				}
			}
		}
	}
}
