package bmff

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

func isBMFFFixture(f fixtures.Fixture) bool { return f.Format == "heic" || f.Format == "avif" }

// TestFixtures: for every HEIC and AVIF fixture, the store is found where
// c2patool put it (straight after ftyp), Digest reproduces the hash in
// c2patool's c2pa.hash.bmff.v3 assertion (and differs exactly when
// c2patool reports a mismatch), and Insert(Strip(f), store) == f.
func TestFixtures(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	digests := 0
	for _, f := range all {
		if !isBMFFFixture(f) {
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
			if _, err := Parse(b); err != nil {
				if !exp.Failed() {
					t.Fatal(err)
				}
				return // truncated: c2patool refuses it too
			}
			st, err := Extract(b)
			if errors.Is(err, ErrNoManifest) {
				if !exp.Failed() {
					t.Fatal("no store, but the oracle read one")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tr, _ := Parse(b)
			if tr.Top[0].Type != "ftyp" || tr.Top[1].Offset != st.Box.Offset {
				t.Errorf("C2PA box at %d, want straight after ftyp", st.Box.Offset)
			}
			var am struct {
				AssertionStore struct {
					BMFF struct {
						Hash string `json:"hash"`
					} `json:"c2pa.hash.bmff.v3"`
				} `json:"assertion_store"`
			}
			if exp.ActiveManifest != "" && json.Unmarshal(exp.Manifests[exp.ActiveManifest], &am) == nil && am.AssertionStore.BMFF.Hash != "" {
				d, err := Digest(sha256.New(), b, DefaultExclusions(), true)
				if err != nil {
					t.Fatal(err)
				}
				mismatch := false
				if exp.ValidationResults != nil && exp.ValidationResults.ActiveManifest != nil {
					for _, s := range exp.ValidationResults.ActiveManifest.Failure {
						mismatch = mismatch || s.Code == "assertion.bmffHash.mismatch"
					}
				}
				if got := base64.StdEncoding.EncodeToString(d); (got == am.AssertionStore.BMFF.Hash) == mismatch {
					t.Errorf("digest %s, assertion %s, c2patool mismatch %v", got, am.AssertionStore.BMFF.Hash, mismatch)
				}
				digests++
			}
			stripped, err := Strip(b)
			if err != nil {
				t.Fatal(err)
			}
			again, bx, data, err := Insert(stripped, st.JUMBF)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, b) || bx.Offset != st.Box.Offset || bx.Size != st.Box.Size || data != st.DataOffset {
				t.Error("Insert(Strip(f), store) differs from f")
			}
		})
	}
	if digests < 6 {
		t.Errorf("checked %d digests against the oracle, want at least 6", digests)
	}
}

type extent struct{ off, n uint64 }

// ilocExtents resolves every item's extents to absolute file ranges
// (construction method 0 only).
func ilocExtents(t *testing.T, b []byte) []extent {
	t.Helper()
	tr, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	iloc := tr.First("/meta/iloc")
	if iloc == nil {
		t.Fatal("no iloc")
	}
	r := &reader{b: b, p: iloc.Offset + iloc.HeaderLen, end: iloc.End()}
	version := r.u8()
	r.skip(3)
	s1, s2 := r.u8(), r.u8()
	offSize, lenSize, baseSize, idxSize := int(s1>>4), int(s1&15), int(s2>>4), int(s2&15)
	if version == 0 {
		idxSize = 0
	}
	n := uint64(r.u16())
	if version == 2 {
		n = uint64(r.u32())
	}
	var out []extent
	for i := uint64(0); i < n; i++ {
		if version < 2 {
			r.skip(2)
		} else {
			r.skip(4)
		}
		method := 0
		if version >= 1 {
			method = int(r.u16() & 15)
		}
		r.skip(2)
		base := r.n(baseSize)
		ec := int(r.u16())
		for e := 0; e < ec; e++ {
			r.skip(idxSize)
			o, l := r.n(offSize), r.n(lenSize)
			if method == 0 {
				out = append(out, extent{base + o, l})
			}
		}
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	return out
}

// TestInsertKeepsImageData: after Insert, every iloc extent still points at
// the same image bytes (the offsets moved with the data), and Strip moves
// them back.
func TestInsertKeepsImageData(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unsigned/sample.heic", "unsigned/sample.avif"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		before := ilocExtents(t, b)
		if len(before) == 0 {
			t.Fatalf("%s: no file extents", name)
		}
		for _, n := range []int{1, 13653, 70000} {
			out, bx, data, err := Insert(b, bytes.Repeat([]byte{0xA5}, n))
			if err != nil {
				t.Fatal(err)
			}
			if bx.Size != InsertedSize(n) || data != bx.Offset+45 || len(out) != len(b)+bx.Size {
				t.Errorf("%s n=%d: box %+v, data at %d", name, n, bx, data)
			}
			after := ilocExtents(t, out)
			for i := range before {
				o, a := before[i], after[i]
				if a.off != o.off+uint64(bx.Size) || !bytes.Equal(out[a.off:a.off+a.n], b[o.off:o.off+o.n]) {
					t.Errorf("%s n=%d: extent %d moved to %d (want %d) or changed", name, n, i, a.off, o.off+uint64(bx.Size))
				}
			}
			back, err := Strip(out)
			if err != nil || !bytes.Equal(back, b) {
				t.Errorf("%s n=%d: Strip(Insert(f)) differs from f (%v)", name, n, err)
			}
			if err := WriteStore(out, bx, data, n-1, []byte{1}); err != nil || out[data+n-1] != 1 {
				t.Errorf("WriteStore: %v", err)
			}
			if err := WriteStore(out, bx, data, n, []byte{1}); !errors.Is(err, ErrOutOfRange) {
				t.Errorf("WriteStore past the store: %v", err)
			}
		}
	}
}

// box builds a box from its type and body parts.
func box(typ string, body ...[]byte) []byte {
	var p []byte
	for _, x := range body {
		p = append(p, x...)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(8+len(p)))
	return append(append(out, typ...), p...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseEdges(t *testing.T) {
	ftyp := box("ftyp", []byte("isom\x00\x00\x00\x00isom"))
	// A size-1 box with a 64-bit size, the QuickTime meta without version
	// and flags, and a size-0 mdat that runs to the end.
	large := append(binary.BigEndian.AppendUint32(nil, 1), "free"...)
	large = binary.BigEndian.AppendUint64(large, 20)
	large = append(large, 1, 2, 3, 4)
	qtMeta := box("meta", box("hdlr", make([]byte, 24)))
	mdat0 := append(binary.BigEndian.AppendUint32(nil, 0), "mdat"...)
	mdat0 = append(mdat0, "pixels"...)
	tr, err := Parse(cat(ftyp, large, qtMeta, mdat0))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Top) != 4 || tr.Top[1].HeaderLen != 16 || tr.Top[1].Size != 20 || tr.Top[3].Size != 14 {
		t.Fatalf("top boxes: %+v %+v %+v", tr.Top[1], tr.Top[2], tr.Top[3])
	}
	if m := tr.First("/meta"); m.HasVersion || tr.First("/meta/hdlr") == nil {
		t.Error("QuickTime meta: version read, or hdlr child not found")
	}
	// An mdat past the end is cut short; anything else is an error.
	cut := cat(ftyp, box("mdat", make([]byte, 10)))
	binary.BigEndian.PutUint32(cut[len(ftyp):], 1000)
	if tr, err := Parse(cut); err != nil || tr.Top[1].Size != 18 {
		t.Errorf("mdat past the end: %v", err)
	}
	copy(cut[len(ftyp)+4:], "moov")
	if _, err := Parse(cut); !errors.Is(err, ErrTruncated) {
		t.Errorf("moov past the end: %v", err)
	}
	// Trailing bytes that are not a box header end the walk.
	if tr, err := Parse(cat(ftyp, []byte{1, 2, 3})); err != nil || len(tr.Top) != 1 {
		t.Errorf("trailing bytes: %v", err)
	}
	deep := box("moov")
	for i := 0; i < MaxDepth+1; i++ {
		deep = box("moov", deep)
	}
	if _, err := Parse(deep); !errors.Is(err, ErrTooDeep) {
		t.Errorf("deep: %v", err)
	}
	if _, err := Parse([]byte("\x00\x00\x00\x04free")); !errors.Is(err, ErrMalformed) {
		t.Errorf("size 4: %v", err)
	}
	major, compat := Brands(ftyp)
	if major != "isom" || len(compat) != 1 || compat[0] != "isom" || !IsBMFF(ftyp) || IsBMFF([]byte("RIFF....WEBP")) {
		t.Errorf("Brands = %q %q", major, compat)
	}
	if _, _, _, err := Insert(box("free"), []byte("x")); !errors.Is(err, ErrNoFtyp) {
		t.Errorf("Insert without ftyp: %v", err)
	}
	// Exclusion filters: length, version and flags, data, subsets.
	l := uint64(20)
	v := uint8(1)
	f := cat(ftyp, large)
	tr, _ = Parse(f)
	for _, tc := range []struct {
		e    Exclusion
		want int
	}{
		{Exclusion{XPath: "/free", Length: &l}, 1},
		{Exclusion{XPath: "/free", Length: new(uint64)}, 0},
		{Exclusion{XPath: "/free", Data: []DataMatch{{Offset: 16, Value: []byte{1, 2}}}}, 1},
		{Exclusion{XPath: "/free", Data: []DataMatch{{Offset: 16, Value: []byte{9}}}}, 0},
		{Exclusion{XPath: "/free", Version: &v}, 1}, // free has no version: not filtered
		{Exclusion{XPath: "/free", Subset: []Subset{{Offset: 16, Length: 0}, {Offset: 99, Length: 1}}}, 1},
	} {
		r, err := exclusionRanges(f, tr, []Exclusion{tc.e}, false)
		if err != nil || len(r) != tc.want {
			t.Errorf("%+v: %d ranges (%v), want %d", tc.e, len(r), err, tc.want)
		}
	}
	if _, err := exclusionRanges(f, tr, []Exclusion{{XPath: "/free", Data: []DataMatch{{Offset: 19, Value: []byte{1, 2}}}}}, false); !errors.Is(err, ErrBadExclusion) {
		t.Errorf("data match past the end: %v", err)
	}
}

// TestSpans checks the offset markers against a hand-worked case.
func TestSpans(t *testing.T) {
	// 100 bytes: boxes at 0 (ftyp, 20 bytes, excluded), 20 and 60.
	got, err := spansToHash(100, []hashRange{{start: 0, length: 20}, {start: 20, length: 1, marker: true}, {start: 60, length: 1, marker: true}})
	if err != nil {
		t.Fatal(err)
	}
	want := []span{{20, 20, true}, {20, 59, false}, {60, 60, true}, {60, 99, false}}
	if len(got) != len(want) {
		t.Fatalf("spans %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("spans %v, want %v", got, want)
		}
	}
	if _, err := spansToHash(10, []hashRange{{start: 5, length: 6}}); !errors.Is(err, ErrBadExclusion) {
		t.Errorf("exclusion past the end: %v", err)
	}
	if s, _ := spansToHash(10, nil); len(s) != 1 || s[0] != (span{0, 9, false}) {
		t.Errorf("no exclusions: %v", s)
	}
}

func fuzzSeeds(f *testing.F) {
	all, _ := fixtures.List()
	for _, fx := range all {
		if isBMFFFixture(fx) {
			if b, err := os.ReadFile(fx.Path); err == nil && len(b) < 160<<10 {
				f.Add(b)
			}
		}
	}
	f.Add(box("ftyp", []byte("avif\x00\x00\x00\x00")))
	f.Add(tinyHEIF())
}

// tinyHEIF is a minimal file with an iloc (version 1, 4-byte offsets and
// lengths, no base offset) whose one extent points into mdat: small, so
// the fuzzer runs fast through the offset fix-ups.
func tinyHEIF() []byte {
	ftyp := box("ftyp", []byte("mif1\x00\x00\x00\x00mif1heic"))
	hdlr := box("hdlr", make([]byte, 4), make([]byte, 4), []byte("pict"), make([]byte, 13))
	ilocBody := []byte{1, 0, 0, 0, 0x44, 0x00}            // version 1; offset/length size 4; base/index size 0
	ilocBody = binary.BigEndian.AppendUint16(ilocBody, 1) // item count
	ilocBody = binary.BigEndian.AppendUint16(ilocBody, 1) // item ID
	ilocBody = binary.BigEndian.AppendUint16(ilocBody, 0) // construction method 0
	ilocBody = binary.BigEndian.AppendUint16(ilocBody, 0) // data reference index
	ilocBody = binary.BigEndian.AppendUint16(ilocBody, 1) // extent count
	offPos := len(ilocBody)
	ilocBody = binary.BigEndian.AppendUint32(ilocBody, 0) // extent offset, set below
	ilocBody = binary.BigEndian.AppendUint32(ilocBody, 4) // extent length
	meta := box("meta", []byte{0, 0, 0, 0}, hdlr, box("iloc", ilocBody))
	f := cat(ftyp, meta, box("mdat", []byte("DATA")))
	ilocAt := len(ftyp) + 8 + 4 + len(hdlr) + 8
	binary.BigEndian.PutUint32(f[ilocAt+offPos:], uint32(len(f)-4))
	return f
}

func TestTinyHEIF(t *testing.T) {
	b := tinyHEIF()
	before := ilocExtents(t, b)
	if len(before) != 1 || string(b[before[0].off:before[0].off+4]) != "DATA" {
		t.Fatalf("tinyHEIF extent %+v does not point at its data", before)
	}
	out, bx, _, err := Insert(b, []byte("store"))
	if err != nil {
		t.Fatal(err)
	}
	after := ilocExtents(t, out)
	if after[0].off != before[0].off+uint64(bx.Size) || string(out[after[0].off:after[0].off+4]) != "DATA" {
		t.Errorf("extent after Insert %+v", after)
	}
}

// FuzzParse: Parse, Extract, Strip, Insert and Digest never panic, and on
// any file Strip accepts, Strip(Insert(Strip(b), s)) == Strip(b).
func FuzzParse(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		Extract(b)
		Digest(sha256.New(), b, DefaultExclusions(), true)
		Digest(sha256.New(), b, []Exclusion{{XPath: "/meta/iloc", Subset: []Subset{{Offset: 4, Length: 0}}}}, false)
		s, err := Strip(b)
		if err != nil {
			return
		}
		out, bx, data, err := Insert(s, []byte("store"))
		if err != nil {
			return
		}
		if !bytes.Equal(out[data:bx.End()], []byte("store")) {
			t.Fatal("store not where Insert says")
		}
		back, err := Strip(out)
		if err != nil {
			t.Fatalf("Strip after Insert: %v", err)
		}
		if !bytes.Equal(back, s) {
			t.Fatal("Strip(Insert(s)) differs from s")
		}
	})
}
