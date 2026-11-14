package c2paseal_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/container/webp"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func webpOpts(t *testing.T) *c2paseal.SignOptions {
	t.Helper()
	td := signtest.TestdataDir(t)
	chain, key, err := c2paseal.LoadSigner(filepath.Join(td, "pki", "leaf-chain.pem"), filepath.Join(td, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &c2paseal.SignOptions{Chain: chain, Signer: key}
}

// TestSignWebP is the phase's check for signing: each WebP layout (VP8L,
// VP8, VP8X with ALPH) signed by C2paSeal validates in C2paSeal and in
// c2patool; so does re-signing a file c2patool signed. The C2PA chunk is
// last, the image chunks are untouched, and the hard-binding exclusion is
// the chunk header and data, as c2pa-rs writes it.
func TestSignWebP(t *testing.T) {
	td := signtest.TestdataDir(t)
	for _, tc := range []struct {
		in        string
		manifests int
	}{
		{"unsigned/small.webp", 1},
		{"unsigned/lossy.webp", 1},
		{"unsigned/alpha.webp", 1},
		{"unsigned/large.webp", 1},
		{"signed/small.webp", 2}, // c2patool's manifest becomes the parent
	} {
		t.Run(tc.in, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(td, tc.in))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := c2paseal.SignAsset(in, webpOpts(t))
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "c2paseal-"+filepath.Base(tc.in))
			if err := os.WriteFile(out, signed.File, 0o644); err != nil {
				t.Fatal(err)
			}
			signtest.CheckFile(t, out)
			t.Logf("store %d bytes (odd: %v, so a pad byte follows the exclusion)", len(signed.Store), len(signed.Store)%2 == 1)

			s, err := c2paseal.ReadBytes(signed.File)
			if err != nil || s.Format != c2paseal.FormatWebP || len(s.Manifests) != tc.manifests {
				t.Fatalf("read back: %v, format %q, %d manifests", err, s.Format, len(s.Manifests))
			}
			st, err := webp.Extract(signed.File)
			if err != nil {
				t.Fatal(err)
			}
			chunks, _ := webp.Chunks(signed.File)
			if chunks[len(chunks)-1] != st.Chunk || !bytes.Equal(st.JUMBF, signed.Store) {
				t.Error("the C2PA chunk is not last, or holds another store")
			}
			stripped, _ := webp.Strip(in)
			if st.Chunk.Offset != len(stripped) || !bytes.Equal(signed.File[:4], stripped[:4]) ||
				!bytes.Equal(signed.File[8:st.Chunk.Offset], stripped[8:]) { // bytes 4-8: the RIFF size
				t.Error("the bytes before the C2PA chunk changed (apart from the RIFF size)")
			}
			a := s.Active.Assertion("c2pa.hash.data")
			if a == nil {
				t.Fatal("no c2pa.hash.data")
			}
			hd, _ := a.Value.(*assertion.DataHash)
			if hd == nil || len(hd.Exclusions) != 1 || hd.Exclusions[0].Start != uint64(st.Chunk.Offset) || hd.Exclusions[0].Length != uint64(st.Chunk.ExclusionLength()) {
				t.Errorf("exclusion %+v, chunk at %d with ExclusionLength %d", hd, st.Chunk.Offset, st.Chunk.ExclusionLength())
			}
		})
	}
}

// TestSignWebPRemote: a remote manifest reference goes into the WebP's XMP
// chunk (with VP8X created and flagged), and the file verifies against the
// store kept outside it.
func TestSignWebPRemote(t *testing.T) {
	td := signtest.TestdataDir(t)
	in, err := os.ReadFile(filepath.Join(td, "unsigned", "lossy.webp"))
	if err != nil {
		t.Fatal(err)
	}
	opts := webpOpts(t)
	opts.RemoteURL = "https://example.com/manifests/lossy.c2pa"
	opts.Sidecar = true
	signed, err := c2paseal.SignAsset(in, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webp.Extract(signed.File); err == nil {
		t.Error("store embedded despite Sidecar")
	}
	x, ok, err := webp.XMP(signed.File)
	if err != nil || !ok || !bytes.Contains(x, []byte(opts.RemoteURL)) {
		t.Fatalf("XMP %q, %v, %v", x, ok, err)
	}
	chunks, _ := webp.Chunks(signed.File)
	if chunks[0].FourCC != webp.FourCCVP8X || chunks[0].Data(signed.File)[0]&0x04 == 0 {
		t.Error("no VP8X with the XMP flag")
	}
	r := c2paseal.VerifyBytes(signed.File, &c2paseal.VerifyOptions{ManifestStore: signed.Store})
	if r.State() != verify.Valid {
		t.Errorf("state %s with the store given, want Valid: %+v", r.State(), r.ActiveManifest)
	}
}

// TestSignWebPEvenStore covers the other parity: a store of even length
// has no pad byte after it. The title is lengthened until the store is
// even; c2patool must accept that file too.
func TestSignWebPEvenStore(t *testing.T) {
	in, err := os.ReadFile(filepath.Join(signtest.TestdataDir(t), "unsigned", "small.webp"))
	if err != nil {
		t.Fatal(err)
	}
	for title := "t"; len(title) < 6; title += "t" {
		opts := webpOpts(t)
		opts.Title = title
		signed, err := c2paseal.SignAsset(in, opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(signed.Store)%2 == 1 {
			continue
		}
		st, _ := webp.Extract(signed.File)
		if st.Chunk.End() != len(signed.File) || st.Chunk.ExclusionLength() != st.Chunk.Size() {
			t.Errorf("even store: chunk %+v in a %d-byte file", st.Chunk, len(signed.File))
		}
		out := filepath.Join(t.TempDir(), "even.webp")
		os.WriteFile(out, signed.File, 0o644)
		signtest.CheckFile(t, out)
		t.Logf("store %d bytes with title %q", len(signed.Store), title)
		return
	}
	t.Fatal("no title gave an even-length store")
}
