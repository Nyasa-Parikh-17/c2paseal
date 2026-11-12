package jpeg

import (
	"bytes"
	"errors"
	"testing"
)

func TestXMP(t *testing.T) {
	exif := seg(APP1, []byte("Exif\x00\x00rest"))
	dqt := seg(0xDB, make([]byte, 65))
	in := jpegOf(seg(APP0, []byte("JFIF\x00")), exif, dqt)
	if _, _, ok, err := XMP(in); ok || err != nil {
		t.Fatalf("XMP of a file without one: %v %v", ok, err)
	}

	out, err := SetXMP(in, []byte("<first/>"))
	if err != nil {
		t.Fatal(err)
	}
	p, s, ok, err := XMP(out)
	if !ok || err != nil || string(p) != "<first/>" {
		t.Fatalf("read back %q %v %v", p, ok, err)
	}
	// Inserted after SOI, APP0 and the Exif APP1, before DQT.
	if want := 2 + len(seg(APP0, []byte("JFIF\x00"))) + len(exif); s.Offset != want {
		t.Errorf("XMP segment at %d, want %d", s.Offset, want)
	}
	// Replaced in place, not duplicated; the rest of the file is unchanged.
	out2, err := SetXMP(out, []byte("<second/>"))
	if err != nil {
		t.Fatal(err)
	}
	if p, _, _, _ := XMP(out2); string(p) != "<second/>" {
		t.Errorf("replaced packet %q", p)
	}
	if n := bytes.Count(out2, []byte(XMPNamespace)); n != 1 {
		t.Errorf("%d XMP segments after replacing", n)
	}
	back, _ := SetXMP(out2, []byte("<first/>"))
	if !bytes.Equal(back, out) {
		t.Error("replacing the packet changed other bytes")
	}

	if _, err := SetXMP(in, make([]byte, maxXMP+1)); !errors.Is(err, ErrXMPTooLarge) {
		t.Errorf("oversized packet: %v", err)
	}
	if _, err := SetXMP([]byte("nope"), nil); !errors.Is(err, ErrNotJPEG) {
		t.Errorf("not a JPEG: %v", err)
	}
}

func FuzzXMP(f *testing.F) {
	fuzzSeeds(f)
	f.Add(jpegOf(seg(APP1, []byte(XMPNamespace+"<x/>"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, _, _, err := XMP(b); err != nil {
			return
		}
		out, err := SetXMP(b, []byte("<p/>"))
		if err != nil {
			return
		}
		if p, _, ok, err := XMP(out); err != nil || !ok || string(p) != "<p/>" {
			t.Fatalf("after SetXMP: %q %v %v", p, ok, err)
		}
	})
}
