package jpeg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
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

// TestFixtures checks Extract against the c2patool oracle for every JPEG:
// where c2patool reads a manifest store we must find the same manifests, and
// where it fails we must return an error.
func TestFixtures(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	signed := 0
	for _, f := range all {
		if f.Format != "jpeg" {
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
			st, err := Extract(b)
			if exp.Failed() {
				if err == nil {
					t.Fatalf("Extract succeeded; c2patool failed with %q", exp.C2patoolError)
				}
				if f.Kind == fixtures.Unsigned && !errors.Is(err, ErrNoManifest) {
					t.Errorf("unsigned file: error %v, want ErrNoManifest", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if f.Kind == fixtures.Signed {
				signed++
			}
			if got, want := manifestLabels(st.Root), exp.ManifestLabels(); !slices.Equal(got, want) {
				t.Errorf("manifest labels = %q, oracle %q", got, want)
			}
			if !bytes.Equal(jumbf.Serialize(st.Root), st.JUMBF) {
				t.Error("store does not round-trip through jumbf")
			}
			for _, s := range st.Segments {
				if s.Marker != APP11 || !bytes.Equal(b[s.Offset:s.Offset+2], []byte{0xFF, APP11}) {
					t.Errorf("segment at %d is not APP11", s.Offset)
				}
			}
		})
	}
	if signed < 5 {
		t.Errorf("only %d signed JPEG fixtures checked", signed)
	}
}

func TestTruncatedFixture(t *testing.T) {
	root, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(root + "/broken/truncated-app11.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(b); !errors.Is(err, ErrTruncated) {
		t.Fatalf("Extract error = %v, want ErrTruncated", err)
	}
}

func TestMultiSegmentFixture(t *testing.T) {
	root, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(root + "/signed/large.jpg")
	if err != nil {
		t.Fatal(err)
	}
	st, err := Extract(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Segments) != 7 {
		t.Errorf("large.jpg: %d APP11 segments, want 7", len(st.Segments))
	}
}

// --- hand-built JPEGs ---------------------------------------------------

func seg(marker byte, payload []byte) []byte {
	return append([]byte{0xFF, marker, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}, payload...)
}

func store(label string) []byte {
	desc := func(l string) *jumbf.Box {
		return &jumbf.Box{Type: jumbf.TypeDescription, Description: &jumbf.Description{
			Toggles: jumbf.ToggleRequestable | jumbf.ToggleLabel, Label: l}}
	}
	return jumbf.Serialize(&jumbf.Box{Type: jumbf.TypeSuperbox, Children: []*jumbf.Box{
		desc(label),
		{Type: jumbf.TypeSuperbox, Children: []*jumbf.Box{desc("urn:c2pa:test"), {Type: "cbor", Payload: bytes.Repeat([]byte{7}, 300)}}},
	}})
}

// app11 splits a JUMBF box into JPEG XT APP11 segments carrying at most
// chunk payload bytes each, in sequence order.
func app11(en uint16, box []byte, chunk int) [][]byte {
	hdr, data := box[:8], box[8:]
	var segs [][]byte
	for z := uint32(1); len(data) > 0; z++ {
		n := min(chunk, len(data))
		p := append([]byte("JP"), byte(en>>8), byte(en))
		p = binary.BigEndian.AppendUint32(p, z)
		p = append(append(p, hdr...), data[:n]...)
		segs = append(segs, seg(APP11, p))
		data = data[n:]
	}
	return segs
}

func jpegOf(parts ...[]byte) []byte {
	b := []byte{0xFF, SOI}
	for _, p := range parts {
		b = append(b, p...)
	}
	b = append(b, seg(SOS, []byte{1, 2, 3})...)
	return append(b, 0x12, 0x34, 0xFF, EOI)
}

func TestExtractBuilt(t *testing.T) {
	s := store("c2pa")
	parts := app11(1, s, 100)
	if len(parts) < 3 {
		t.Fatal("test store should span several segments")
	}
	app0 := seg(APP0, []byte("JFIF\x00"))

	tests := []struct {
		name     string
		in       []byte
		wantSegs int
		wantErr  error
	}{
		{"in order", jpegOf(app0, bytes.Join(parts, nil)), len(parts), nil},
		{"out of order", jpegOf(parts[2], parts[0], app0, parts[1], bytes.Join(parts[3:], nil)), len(parts), nil},
		{"fill bytes", jpegOf([]byte{0xFF, 0xFF}, app0, []byte{0xFF}, bytes.Join(parts, nil)), len(parts), nil},
		{"standalone TEM", jpegOf([]byte{0xFF, 0x01}, bytes.Join(parts, nil)), len(parts), nil},
		{"other APP11 ignored", jpegOf(seg(APP11, []byte("XX123")), app11(9, jumbf.Serialize(&jumbf.Box{Type: "json", Payload: []byte("{}")}), 10)[0], bytes.Join(parts, nil)), len(parts), nil},
		{"no APP11", jpegOf(app0), 0, ErrNoManifest},
		{"non-c2pa JUMBF", jpegOf(bytes.Join(app11(1, store("other"), 100), nil)), 0, ErrNoManifest},
		{"missing segment", jpegOf(parts[0], bytes.Join(parts[2:], nil)), 0, ErrBadSegment},
		{"duplicate sequence", jpegOf(parts[0], parts[0], bytes.Join(parts[1:], nil)), 0, ErrBadSegment},
		{"last segment lost", jpegOf(bytes.Join(parts[:len(parts)-1], nil)), 0, ErrTruncated},
		{"two stores", jpegOf(bytes.Join(parts, nil), bytes.Join(app11(2, s, 100), nil)), 0, ErrMultipleStores},
		{"short JPEG XT header", jpegOf(seg(APP11, []byte("JP\x00\x01"))), 0, ErrBadSegment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := Extract(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Extract error = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !bytes.Equal(st.JUMBF, s) {
				t.Error("reassembled store differs from the original")
			}
			if len(st.Segments) != tt.wantSegs {
				t.Errorf("%d segments, want %d", len(st.Segments), tt.wantSegs)
			}
			if !slices.IsSortedFunc(st.Segments, func(a, b Segment) int { return a.Offset - b.Offset }) {
				t.Error("segments not in file order")
			}
		})
	}
}

func TestExtractExtendedHeader(t *testing.T) {
	s := store("c2pa")
	ext := append([]byte{0, 0, 0, 1}, s[4:8]...)
	ext = binary.BigEndian.AppendUint64(ext, uint64(len(s)+8))
	ext = append(ext, s[8:]...)
	// Split manually: every segment repeats the 16-byte header.
	hdr, data := ext[:16], ext[16:]
	var parts []byte
	for z := uint32(1); len(data) > 0; z++ {
		n := min(120, len(data))
		p := binary.BigEndian.AppendUint32([]byte("JP\x00\x01"), z)
		parts = append(parts, seg(APP11, append(append(p, hdr...), data[:n]...))...)
		data = data[n:]
	}
	st, err := Extract(jpegOf(parts))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.JUMBF, ext) {
		t.Error("reassembled extended-length store differs")
	}
}

func TestSegments(t *testing.T) {
	b := jpegOf([]byte{0xFF}, seg(APP0, []byte("JFIF\x00")), seg(APP1, nil))
	segs, err := Segments(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Segment{
		{SOI, 0, 2},
		{APP0, 3, 9}, // after one fill byte
		{APP1, 12, 4},
		{SOS, 16, 7},
	}
	if !slices.Equal(segs, want) {
		t.Errorf("Segments = %v, want %v", segs, want)
	}

	errs := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrNotJPEG},
		{"PNG", []byte("\x89PNG\r\n\x1a\n"), ErrNotJPEG},
		{"SOI only", []byte{0xFF, SOI}, ErrTruncated},
		{"garbage after SOI", []byte{0xFF, SOI, 0x00}, ErrBadSegment},
		{"stuffed byte", []byte{0xFF, SOI, 0xFF, 0x00}, ErrBadSegment},
		{"length below 2", []byte{0xFF, SOI, 0xFF, APP0, 0, 1}, ErrBadSegment},
		{"length past end", []byte{0xFF, SOI, 0xFF, APP0, 0, 10, 1}, ErrTruncated},
		{"cut length", []byte{0xFF, SOI, 0xFF, APP0, 0}, ErrTruncated},
		{"only fill bytes", []byte{0xFF, SOI, 0xFF, 0xFF}, ErrTruncated},
	}
	for _, tt := range errs {
		if _, err := Segments(tt.in); !errors.Is(err, tt.want) {
			t.Errorf("%s: error %v, want %v", tt.name, err, tt.want)
		}
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(jpegOf(bytes.Join(app11(1, store("c2pa"), 64), nil)))
	f.Add(jpegOf(seg(APP0, []byte("JFIF\x00"))))
	if dir, err := fixtures.Dir(); err == nil {
		for _, name := range []string{"signed/small.jpg", "signed/exif.jpg", "unsigned/small.jpg"} {
			if b, err := os.ReadFile(dir + "/" + name); err == nil {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := Extract(b)
		if err != nil {
			return
		}
		for _, s := range st.Segments {
			if s.Offset < 0 || s.End() > len(b) || s.Marker != APP11 {
				t.Fatalf("bad segment %+v in %d-byte input", s, len(b))
			}
		}
	})
}
