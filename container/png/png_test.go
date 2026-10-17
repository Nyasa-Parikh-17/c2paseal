package png

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

func manifestLabels(root *jumbf.Box) []string {
	var labels []string
	for _, c := range root.Contents() {
		if c.IsSuperbox() {
			labels = append(labels, c.Label())
		}
	}
	slices.Sort(labels)
	return labels
}

// TestFixtures checks Extract against the oracle and the byte-exact round
// trip Insert(Strip(f), Extract(f)) == f for every PNG fixture.
func TestFixtures(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	roundTrips := 0
	for _, f := range all {
		if f.Format != "png" {
			continue
		}
		t.Run(f.String(), func(t *testing.T) {
			b, err := os.ReadFile(f.Path)
			if err != nil {
				t.Fatal(err)
			}
			exp, err := f.Expected()
			if err != nil {
				t.Fatal(err)
			}
			chunks, err := Chunks(b)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range chunks {
				if !c.CRCValid {
					t.Errorf("%s chunk at %d: bad CRC", c.Type, c.Offset)
				}
			}
			st, err := Extract(b)
			if exp.Failed() {
				if err == nil {
					t.Fatalf("Extract succeeded; c2patool failed with %q", exp.C2patoolError)
				}
				if f.Kind == fixtures.Unsigned && !errors.Is(err, ErrNoManifest) {
					t.Errorf("unsigned: error %v, want ErrNoManifest", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if got, want := manifestLabels(st.Root), exp.ManifestLabels(); !slices.Equal(got, want) {
				t.Errorf("manifest labels = %q, oracle %q", got, want)
			}

			stripped, err := Strip(b)
			if err != nil {
				t.Fatal(err)
			}
			out, c, err := Insert(stripped, st.JUMBF)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, b) {
				t.Fatalf("round trip differs (got %d bytes, want %d)", len(out), len(b))
			}
			if c != st.Chunk {
				t.Errorf("Insert chunk %+v, Extract chunk %+v", c, st.Chunk)
			}
			roundTrips++
		})
	}
	if roundTrips < 4 {
		t.Errorf("only %d PNG fixtures round-tripped", roundTrips)
	}
}

func TestStripRestoresOriginal(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	for signed, unsigned := range map[string]string{
		"signed/small.png":   "unsigned/small.png",
		"signed/ts.png":      "unsigned/small.png",
		"signed/large.png":   "unsigned/large.png",
		"unsigned/small.png": "unsigned/small.png",
	} {
		s, err1 := os.ReadFile(filepath.Join(dir, signed))
		u, err2 := os.ReadFile(filepath.Join(dir, unsigned))
		if err := errors.Join(err1, err2); err != nil {
			t.Fatal(err)
		}
		got, err := Strip(s)
		if err != nil {
			t.Errorf("Strip(%s): %v", signed, err)
		} else if !bytes.Equal(got, u) {
			t.Errorf("Strip(%s) != %s", signed, unsigned)
		}
	}
}

// --- hand-built PNGs ----------------------------------------------------

func chunk(typ string, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	b = append(append(b, typ...), data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b[4:]))
}

func pngOf(parts ...[]byte) []byte {
	b := []byte(Signature)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

var (
	ihdr = chunk(TypeIHDR, make([]byte, 13))
	idat = chunk("IDAT", []byte{1, 2, 3})
	iend = chunk(TypeIEND, nil)
)

func testStore() []byte {
	return jumbf.Serialize(&jumbf.Box{Type: jumbf.TypeSuperbox, Children: []*jumbf.Box{
		{Type: jumbf.TypeDescription, Description: &jumbf.Description{Toggles: jumbf.ToggleLabel, Label: "c2pa"}},
		{Type: "cbor", Payload: []byte{0xA0}},
	}})
}

func TestInsertPlacement(t *testing.T) {
	s := testStore()
	plte := chunk("PLTE", []byte{0, 0, 0})
	gama := chunk("gAMA", []byte{0, 0, 0, 1})
	in := pngOf(ihdr, plte, gama, idat, idat, iend)
	out, c, err := Insert(in, s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Offset != len(Signature)+len(ihdr) {
		t.Errorf("caBX at %d, want straight after IHDR (%d)", c.Offset, len(Signature)+len(ihdr))
	}
	if len(out)-len(in) != InsertedSize(len(s)) {
		t.Errorf("inserted %d bytes, InsertedSize says %d", len(out)-len(in), InsertedSize(len(s)))
	}
	chunks, err := Chunks(out)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, ch := range chunks {
		types = append(types, ch.Type)
		if !ch.CRCValid {
			t.Errorf("%s: bad CRC after Insert", ch.Type)
		}
	}
	if want := []string{"IHDR", "caBX", "PLTE", "gAMA", "IDAT", "IDAT", "IEND"}; !slices.Equal(types, want) {
		t.Errorf("chunk order %v, want %v", types, want)
	}
	st, err := Extract(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.JUMBF, s) {
		t.Error("extracted store differs")
	}
	if back, _ := Strip(out); !bytes.Equal(back, in) {
		t.Error("Strip(Insert(x)) != x")
	}
}

func TestBadCRCStillReads(t *testing.T) {
	c := chunk(TypeC2PA, testStore())
	c[len(c)-1] ^= 0xFF
	st, err := Extract(pngOf(ihdr, c, idat, iend))
	if err != nil {
		t.Fatalf("Extract with bad caBX CRC: %v (c2pa-rs ignores CRCs)", err)
	}
	if st.Chunk.CRCValid {
		t.Error("CRCValid = true for a corrupted CRC")
	}
}

func TestTrailingDataKept(t *testing.T) {
	in := pngOf(ihdr, idat, iend, []byte("trailer"))
	out, _, err := Insert(in, testStore())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(out, []byte("trailer")) {
		t.Error("bytes after IEND lost")
	}
}

func TestErrors(t *testing.T) {
	s := testStore()
	ca := chunk(TypeC2PA, s)
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"not PNG", []byte("GIF89a"), ErrNotPNG},
		{"signature only", pngOf(), ErrTruncated},
		{"no IEND", pngOf(ihdr, idat), ErrTruncated},
		{"chunk past end", pngOf(ihdr, []byte{0, 0, 1, 0, 'I', 'D', 'A', 'T', 1, 2}), ErrTruncated},
		{"huge length", pngOf([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'I', 'D', 'A', 'T', 0, 0, 0, 0}), ErrTruncated},
		{"no manifest", pngOf(ihdr, idat, iend), ErrNoManifest},
		{"two caBX", pngOf(ihdr, ca, ca, idat, iend), ErrMultipleStores},
		{"bad JUMBF", pngOf(ihdr, chunk(TypeC2PA, []byte{0, 0, 0, 3, 'j', 'u', 'm', 'b'}), iend), jumbf.ErrBadLength},
	}
	for _, tt := range tests {
		if _, err := Extract(tt.in); !errors.Is(err, tt.want) {
			t.Errorf("%s: Extract error %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, _, err := Insert(pngOf(ihdr, ca, iend), s); !errors.Is(err, ErrHasManifest) {
		t.Errorf("insert twice: %v, want ErrHasManifest", err)
	}
	if _, _, err := Insert(pngOf(idat, iend), s); !errors.Is(err, ErrNoIHDR) {
		t.Errorf("no IHDR: %v, want ErrNoIHDR", err)
	}
	if _, err := Strip(pngOf(ihdr)); !errors.Is(err, ErrTruncated) {
		t.Errorf("Strip truncated: %v, want ErrTruncated", err)
	}
}

func fuzzSeeds(f *testing.F) {
	f.Add(pngOf(ihdr, chunk(TypeC2PA, testStore()), idat, iend))
	f.Add(pngOf(ihdr, idat, iend, []byte("x")))
	if dir, err := fixtures.Dir(); err == nil {
		for _, name := range []string{"signed/small.png", "unsigned/small.png"} {
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				f.Add(b)
			}
		}
	}
}

// FuzzChunks checks the chunk walker never panics and returns contiguous,
// in-bounds chunks ending with IEND.
func FuzzChunks(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		chunks, err := Chunks(b)
		if err != nil {
			return
		}
		off := len(Signature)
		for _, c := range chunks {
			if c.Offset != off || c.End() > len(b) {
				t.Fatalf("chunk %+v not contiguous/in bounds (want offset %d, len %d)", c, off, len(b))
			}
			off = c.End()
		}
		if chunks[len(chunks)-1].Type != TypeIEND {
			t.Fatal("walk did not end at IEND")
		}
	})
}

// FuzzStripInsert checks that re-inserting an extracted store into the
// stripped file gives back the same store.
func FuzzStripInsert(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := Extract(b)
		if err != nil {
			return
		}
		stripped, err := Strip(b)
		if err != nil {
			t.Fatalf("Extract ok but Strip failed: %v", err)
		}
		out, _, err := Insert(stripped, st.JUMBF)
		if errors.Is(err, ErrNoIHDR) {
			return
		}
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}
		st2, err := Extract(out)
		if err != nil {
			t.Fatalf("Extract after Insert: %v", err)
		}
		if !bytes.Equal(st2.JUMBF, st.JUMBF) {
			t.Fatal("store changed across Strip+Insert")
		}
	})
}
