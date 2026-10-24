package jpeg

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// TestRoundTripFixtures checks Insert(Strip(f), Extract(f)) == f for every
// JPEG fixture with a readable manifest store.
func TestRoundTripFixtures(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range all {
		if f.Format != "jpeg" {
			continue
		}
		b, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		st, err := Extract(b)
		if err != nil {
			continue
		}
		n++
		t.Run(f.String(), func(t *testing.T) {
			stripped, err := Strip(b)
			if err != nil {
				t.Fatal(err)
			}
			out, segs, err := Insert(stripped, st.JUMBF)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, b) {
				t.Fatalf("round trip differs (got %d bytes, want %d)", len(out), len(b))
			}
			if len(segs) != len(st.Segments) {
				t.Fatalf("Insert reported %d segments, Extract found %d", len(segs), len(st.Segments))
			}
			for i := range segs {
				if segs[i] != st.Segments[i] {
					t.Errorf("segment %d: Insert %+v, Extract %+v", i, segs[i], st.Segments[i])
				}
			}
			if got := len(out) - len(stripped); got != InsertedSize(len(st.JUMBF), 8) {
				t.Errorf("inserted %d bytes, InsertedSize says %d", got, InsertedSize(len(st.JUMBF), 8))
			}
		})
	}
	if n < 9 {
		t.Errorf("only %d JPEG fixtures round-tripped", n)
	}
}

// TestStripRestoresOriginal: c2patool only adds APP11 segments, so stripping
// a signed fixture must give back its unsigned source exactly.
func TestStripRestoresOriginal(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	for signed, unsigned := range map[string]string{
		"signed/small.jpg":            "unsigned/small.jpg",
		"signed/exif.jpg":             "unsigned/exif.jpg",
		"signed/large.jpg":            "unsigned/large.jpg",
		"signed/titled-ts.jpg":        "unsigned/small.jpg",
		"signed/edited.jpg":           "unsigned/small.jpg",
		"broken/bad-jumbf-length.jpg": "unsigned/small.jpg",
		"unsigned/small.jpg":          "unsigned/small.jpg",
	} {
		s, err1 := os.ReadFile(filepath.Join(dir, signed))
		u, err2 := os.ReadFile(filepath.Join(dir, unsigned))
		if err := errors.Join(err1, err2); err != nil {
			t.Fatal(err)
		}
		got, err := Strip(s)
		if err != nil {
			t.Errorf("Strip(%s): %v", signed, err)
			continue
		}
		if !bytes.Equal(got, u) {
			t.Errorf("Strip(%s) != %s", signed, unsigned)
		}
	}
}

func TestSegmentCount(t *testing.T) {
	tests := []struct{ n, want int }{
		{0, 0}, {1, 1}, {8, 1}, {MaxChunk - 1, 1}, {MaxChunk, 1}, {MaxChunk + 1, 2},
		{2 * MaxChunk, 2}, {2*MaxChunk + 1, 3}, {10 * MaxChunk, 10}, {-5, 0},
	}
	for _, tt := range tests {
		if got := SegmentCount(tt.n); got != tt.want {
			t.Errorf("SegmentCount(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

// storeOfSize builds a valid manifest store of exactly n bytes (n >= 64).
func storeOfSize(t *testing.T, n int) []byte {
	t.Helper()
	root := &jumbf.Box{Type: jumbf.TypeSuperbox, Children: []*jumbf.Box{
		{Type: jumbf.TypeDescription, Description: &jumbf.Description{Toggles: jumbf.ToggleLabel, Label: "c2pa"}},
		{Type: "cbor"},
	}}
	root.Children[1].Payload = make([]byte, n-root.Size())
	b := jumbf.Serialize(root)
	if len(b) != n {
		t.Fatalf("built store of %d bytes, want %d", len(b), n)
	}
	return b
}

// TestInsertSizes inserts stores around the segment boundaries and checks
// segment sizes, InsertedSize and that Extract gets the store back.
func TestInsertSizes(t *testing.T) {
	base := jpegOf(seg(APP0, []byte("JFIF\x00")))
	for _, n := range []int{64, MaxChunk - 1, MaxChunk, MaxChunk + 1, 2*MaxChunk + 7, 5 * MaxChunk} {
		s := storeOfSize(t, n)
		out, segs, err := Insert(base, s)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(segs) != SegmentCount(n) {
			t.Errorf("n=%d: %d segments, SegmentCount says %d", n, len(segs), SegmentCount(n))
		}
		if len(out)-len(base) != InsertedSize(n, 8) {
			t.Errorf("n=%d: inserted %d bytes, InsertedSize says %d", n, len(out)-len(base), InsertedSize(n, 8))
		}
		for _, sg := range segs {
			if sg.Length-2 > 0xFFFF {
				t.Errorf("n=%d: segment length field %d exceeds 65535", n, sg.Length-2)
			}
		}
		st, err := Extract(out)
		if err != nil {
			t.Fatalf("n=%d: Extract: %v", n, err)
		}
		if !bytes.Equal(st.JUMBF, s) {
			t.Errorf("n=%d: extracted store differs", n)
		}
	}
}

func TestInsertPlacement(t *testing.T) {
	s := storeOfSize(t, 100)
	app0a := seg(APP0, []byte("JFIF\x00"))
	app0b := seg(APP0, []byte("JFXX\x00"))
	app1 := seg(APP1, []byte("Exif\x00\x00"))
	tests := []struct {
		name string
		in   []byte
		at   int
	}{
		{"bare", jpegOf(), 2},
		{"after APP0", jpegOf(app0a, app1), 2 + len(app0a)},
		{"after last APP0", jpegOf(app0a, app1, app0b), 2 + len(app0a) + len(app1) + len(app0b)},
		{"before APP1 like c2pa-rs", jpegOf(app1), 2},
	}
	for _, tt := range tests {
		_, segs, err := Insert(tt.in, s)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if segs[0].Offset != tt.at {
			t.Errorf("%s: inserted at %d, want %d", tt.name, segs[0].Offset, tt.at)
		}
	}
}

func TestInsertErrors(t *testing.T) {
	s := storeOfSize(t, 100)
	signed, _, err := Insert(jpegOf(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Insert(signed, s); !errors.Is(err, ErrHasManifest) {
		t.Errorf("insert twice: %v, want ErrHasManifest", err)
	}
	if _, _, err := Insert(jpegOf(), []byte("not a box")); !errors.Is(err, ErrBadSegment) {
		t.Errorf("bad store: %v, want ErrBadSegment", err)
	}
	if _, _, err := Insert([]byte("nope"), s); !errors.Is(err, ErrNotJPEG) {
		t.Errorf("not a JPEG: %v, want ErrNotJPEG", err)
	}
	if _, err := Strip([]byte{0xFF, SOI, 0xFF}); !errors.Is(err, ErrTruncated) {
		t.Errorf("Strip truncated: %v, want ErrTruncated", err)
	}
}

func fuzzSeeds(f *testing.F) {
	f.Add(jpegOf(bytes.Join(app11(1, store("c2pa"), 64), nil)))
	f.Add(jpegOf([]byte{0xFF, 0xFF, 0xFF, 0x01}, seg(APP0, []byte("JFIF\x00"))))
	if dir, err := fixtures.Dir(); err == nil {
		for _, name := range []string{"signed/small.jpg", "signed/exif.jpg", "unsigned/small.jpg"} {
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				f.Add(b)
			}
		}
	}
}

// FuzzSegments checks the marker walker never panics and returns segments
// that start at SOI, stay in bounds and do not overlap.
func FuzzSegments(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		segs, err := Segments(b)
		if err != nil {
			return
		}
		if segs[0] != (Segment{SOI, 0, 2}) {
			t.Fatalf("first segment %+v is not SOI", segs[0])
		}
		prev := 0
		for _, s := range segs {
			if s.Offset < prev || s.End() > len(b) || b[s.Offset] != 0xFF || b[s.Offset+1] != s.Marker {
				t.Fatalf("bad segment %+v (prev end %d, len %d)", s, prev, len(b))
			}
			prev = s.End()
		}
		if last := segs[len(segs)-1].Marker; last != SOS && last != EOI {
			t.Fatalf("walk ended on marker 0x%02X", last)
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

// TestWriteStore: overwriting store bytes in place, across segment
// boundaries, gives the same file as inserting the modified store.
func TestWriteStore(t *testing.T) {
	base := jpegOf(seg(APP0, []byte("JFIF\x00")))
	s := storeOfSize(t, 3*MaxChunk+500)
	file, segs, err := Insert(base, s)
	if err != nil {
		t.Fatal(err)
	}
	modified := bytes.Clone(s)
	for _, w := range []struct{ off, n int }{
		{100, 50},                  // inside segment 1
		{MaxChunk - 10, 40},        // straddles segments 1 and 2
		{2*MaxChunk - 5, MaxChunk}, // spans segment 3 entirely into 4
		{len(s) - 7, 7},            // last bytes
	} {
		data := bytes.Repeat([]byte{byte(w.off)}, w.n)
		copy(modified[w.off:], data)
		if err := WriteStore(file, segs, 8, w.off, data); err != nil {
			t.Fatalf("WriteStore(%d, %d): %v", w.off, w.n, err)
		}
	}
	want, _, err := Insert(base, modified)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(file, want) {
		t.Fatal("in-place writes differ from inserting the modified store")
	}
	if err := WriteStore(file, segs, 8, len(s)-2, []byte{1, 2, 3}); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("write past store end: %v, want ErrOutOfRange", err)
	}
}
