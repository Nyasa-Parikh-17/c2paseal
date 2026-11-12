package png

import (
	"bytes"
	"compress/zlib"
	"errors"
	"testing"
)

func itxt(keyword string, compressed bool, text []byte) []byte {
	data := append([]byte(keyword), 0)
	if compressed {
		var z bytes.Buffer
		w := zlib.NewWriter(&z)
		w.Write(text)
		w.Close()
		data = append(data, 1, 0, 0, 0)
		return chunk(TypeITXt, append(data, z.Bytes()...))
	}
	data = append(data, 0, 0, 'e', 'n', 0, 0)
	return chunk(TypeITXt, append(data, text...))
}

func TestXMP(t *testing.T) {
	in := pngOf(ihdr, itxt("Comment", false, []byte("hi")), idat, iend)
	if _, ok, err := XMP(in); ok || err != nil {
		t.Fatalf("XMP of a file without one: %v %v", ok, err)
	}
	out, err := SetXMP(in, []byte("<first/>"))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok, err := XMP(out); !ok || err != nil || string(p) != "<first/>" {
		t.Fatalf("read back %q %v %v", p, ok, err)
	}
	chunks, err := Chunks(out)
	if err != nil {
		t.Fatal(err)
	}
	if chunks[1].Type != TypeITXt || !chunks[1].CRCValid {
		t.Errorf("new chunk %+v is not a valid iTXt straight after IHDR", chunks[1])
	}
	out2, err := SetXMP(out, []byte("<second/>"))
	if err != nil {
		t.Fatal(err)
	}
	if p, _, _ := XMP(out2); string(p) != "<second/>" {
		t.Errorf("replaced packet %q", p)
	}
	if back, _ := SetXMP(out2, []byte("<first/>")); !bytes.Equal(back, out) {
		t.Error("replacing the packet changed other bytes")
	}

	// A compressed packet (as some tools write) is read too.
	z := pngOf(ihdr, itxt(XMPKeyword, true, []byte("<zipped/>")), idat, iend)
	if p, ok, err := XMP(z); !ok || err != nil || string(p) != "<zipped/>" {
		t.Errorf("compressed packet: %q %v %v", p, ok, err)
	}
	bad := pngOf(ihdr, chunk(TypeITXt, []byte(XMPKeyword+"\x00\x01\x00")), idat, iend)
	if _, _, err := XMP(bad); !errors.Is(err, ErrBadITXt) {
		t.Errorf("truncated iTXt: %v", err)
	}
	if _, err := SetXMP(pngOf(idat, iend), nil); !errors.Is(err, ErrNoIHDR) {
		t.Errorf("no IHDR: %v", err)
	}
}

func FuzzXMP(f *testing.F) {
	fuzzSeeds(f)
	f.Add(pngOf(ihdr, itxt(XMPKeyword, false, []byte("<x/>")), idat, iend))
	f.Add(pngOf(ihdr, itxt(XMPKeyword, true, []byte("<x/>")), idat, iend))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, _, err := XMP(b); err != nil {
			return
		}
		out, err := SetXMP(b, []byte("<p/>"))
		if err != nil {
			return
		}
		if p, ok, err := XMP(out); err != nil || !ok || string(p) != "<p/>" {
			t.Fatalf("after SetXMP: %q %v %v", p, ok, err)
		}
	})
}
