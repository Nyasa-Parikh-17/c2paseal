package webp

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vp8x(t *testing.T, b []byte) (flags byte, w, h int) {
	t.Helper()
	chunks, err := Chunks(b)
	if err != nil {
		t.Fatal(err)
	}
	if chunks[0].FourCC != FourCCVP8X {
		t.Fatalf("first chunk is %q, want VP8X", chunks[0].FourCC)
	}
	d := chunks[0].Data(b)
	get := func(p []byte) int { return int(p[0]) | int(p[1])<<8 | int(p[2])<<16 }
	return d[0], get(d[4:7]) + 1, get(d[7:10]) + 1
}

// TestSetXMP covers the three WebP layouts: lossless (VP8L) and lossy (VP8)
// simple files get a VP8X built from the image size; an extended file
// (VP8X, ALPH, VP8) keeps its flags and gains the XMP one. The XMP chunk
// goes before the C2PA chunk of a signed file; setting it again replaces it.
func TestSetXMP(t *testing.T) {
	packet := []byte(`<x:xmpmeta xmlns:x="adobe:ns:meta/">odd</x:xmpmeta>`)
	for _, tc := range []struct {
		file       string
		flagsAfter byte
	}{
		{"unsigned/small.webp", flagXMP},             // VP8L, no alpha used
		{"unsigned/lossy.webp", flagXMP},             // VP8
		{"unsigned/alpha.webp", flagXMP | flagAlpha}, // already extended, alpha
		{"signed/small.webp", flagXMP},
	} {
		t.Run(tc.file, func(t *testing.T) {
			b := fixture(t, tc.file)
			out, err := SetXMP(b, packet)
			if err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint32(out[4:8])+8 != uint32(len(out)) {
				t.Error("wrong RIFF size")
			}
			got, ok, err := XMP(out)
			if err != nil || !ok || !bytes.Equal(got, packet) {
				t.Fatalf("XMP = %q, %v, %v", got, ok, err)
			}
			flags, w, h := vp8x(t, out)
			if flags != tc.flagsAfter || w != 64 || h != 48 {
				t.Errorf("VP8X flags %#x, %dx%d; want %#x, 64x48", flags, w, h, tc.flagsAfter)
			}
			chunks, _ := Chunks(out)
			last := chunks[len(chunks)-1].FourCC
			if _, signed := Extract(b); signed == nil && last != FourCCC2PA {
				t.Errorf("signed file: last chunk %q, want C2PA", last)
			}
			// Everything else is kept: the image chunks' bytes are unchanged.
			for _, c := range chunks {
				if c.FourCC == FourCCVP8 || c.FourCC == FourCCVP8L || c.FourCC == "ALPH" {
					if !bytes.Contains(b, out[c.Offset:c.Offset+c.Size()]) {
						t.Errorf("%s chunk changed", c.FourCC)
					}
				}
			}
			// Again: replaced in place, not added.
			again, err := SetXMP(out, []byte("<b/>"))
			if err != nil {
				t.Fatal(err)
			}
			if p, _, _ := XMP(again); string(p) != "<b/>" || len(again) != len(out)-len(packet)-1+4 {
				t.Errorf("second SetXMP: %q, %d bytes", p, len(again))
			}
		})
	}
	if _, err := SetXMP(riff([2]string{"ICCP", "x"}), packet); err == nil {
		t.Error("SetXMP without an image chunk succeeded")
	}
}

func FuzzXMP(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := SetXMP(b, []byte("<p/>"))
		if err != nil {
			return
		}
		if p, ok, err := XMP(out); err != nil || !ok || string(p) != "<p/>" {
			t.Fatalf("XMP after SetXMP: %q %v %v", p, ok, err)
		}
	})
}
