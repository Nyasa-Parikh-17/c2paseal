package c2paseal_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/container/bmff"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// mdat returns the data of the top-level mdat box.
func mdat(t *testing.T, b []byte) []byte {
	t.Helper()
	tr, err := bmff.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m := tr.First("/mdat")
	if m == nil {
		t.Fatal("no mdat")
	}
	return b[m.Offset+m.HeaderLen : m.End()]
}

// TestSignBMFF is the phase's first check: HEIC and AVIF files signed by
// C2paSeal validate in c2patool (and in C2paSeal). The C2PA box goes
// straight after ftyp, the image data is untouched, the hard binding is
// c2pa.hash.bmff.v3, and re-signing a c2patool-signed file keeps it as the
// parent.
func TestSignBMFF(t *testing.T) {
	td := signtest.TestdataDir(t)
	chain, key, err := c2paseal.LoadSigner(filepath.Join(td, "pki", "leaf-chain.pem"), filepath.Join(td, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in, format string
		manifests  int
	}{
		{"unsigned/sample.heic", c2paseal.FormatHEIC, 1},
		{"unsigned/sample.avif", c2paseal.FormatAVIF, 1},
		{"signed/sample.avif", c2paseal.FormatAVIF, 2},
		{"signed/sample.heic", c2paseal.FormatHEIC, 2},
	} {
		t.Run(tc.in, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(td, tc.in))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := c2paseal.SignAsset(in, &c2paseal.SignOptions{Chain: chain, Signer: key, Title: filepath.Base(tc.in)})
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "c2paseal-"+filepath.Base(tc.in))
			if err := os.WriteFile(out, signed.File, 0o644); err != nil {
				t.Fatal(err)
			}
			signtest.CheckFile(t, out)

			s, err := c2paseal.ReadBytes(signed.File)
			if err != nil || s.Format != tc.format || len(s.Manifests) != tc.manifests {
				t.Fatalf("read back: %v, format %q, %d manifests", err, s.Format, len(s.Manifests))
			}
			if a := s.Active.Assertion(assertion.LabelBMFFHashV3); a == nil || s.Active.Assertion(assertion.LabelDataHash) != nil {
				t.Error("hard binding is not c2pa.hash.bmff.v3 alone")
			}
			tr, _ := bmff.Parse(signed.File)
			st, err := bmff.Extract(signed.File)
			if err != nil || tr.Top[0].Type != "ftyp" || tr.Top[1].Offset != st.Box.Offset || !bytes.Equal(st.JUMBF, signed.Store) {
				t.Errorf("C2PA box not straight after ftyp, or another store (%v)", err)
			}
			if !bytes.Equal(mdat(t, signed.File), mdat(t, in)) {
				t.Error("image data changed")
			}
			r := c2paseal.VerifyBytes(signed.File, nil)
			found := false
			for _, st := range r.ActiveManifest {
				found = found || st.Code == verify.AssertionBMFFHashMatch
			}
			if !found {
				t.Errorf("no %s status: %+v", verify.AssertionBMFFHashMatch, r.ActiveManifest)
			}
		})
	}
}

// TestSignBMFFSidecar: with the store kept outside, the file gains no box
// and still verifies against the store.
func TestSignBMFFSidecar(t *testing.T) {
	td := signtest.TestdataDir(t)
	chain, key, err := c2paseal.LoadSigner(filepath.Join(td, "pki", "leaf-chain.pem"), filepath.Join(td, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.ReadFile(filepath.Join(td, "unsigned", "sample.avif"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := c2paseal.SignAsset(in, &c2paseal.SignOptions{Chain: chain, Signer: key, Sidecar: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed.File, in) {
		t.Error("sidecar signing changed the file")
	}
	if st := c2paseal.VerifyBytes(signed.File, &c2paseal.VerifyOptions{ManifestStore: signed.Store}).State(); st != verify.Valid {
		t.Errorf("state %s, want Valid", st)
	}
	// A remote reference needs XMP, which is not written into BMFF files yet.
	if _, err := c2paseal.SignAsset(in, &c2paseal.SignOptions{Chain: chain, Signer: key, RemoteURL: "https://example.com/m.c2pa", Sidecar: true}); err == nil {
		t.Error("remote reference in an AVIF accepted")
	}
}
