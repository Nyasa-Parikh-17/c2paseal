package webp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
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

// TestFixtures checks Extract against the oracle, the c2pa.hash.data
// exclusion c2patool wrote against ExclusionLength, and the byte-exact
// round trip Insert(Strip(f), Extract(f)) == f, for every WebP fixture.
func TestFixtures(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	signed := 0
	for _, f := range all {
		if f.Format != "webp" {
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
			if _, err := Chunks(b); err != nil {
				// A cut-off chunk is unreadable for c2patool too.
				if !exp.Failed() {
					t.Fatal(err)
				}
				if _, err := Extract(b); !errors.Is(err, ErrTruncated) {
					t.Errorf("Extract on a truncated file: %v", err)
				}
				return
			}
			st, err := Extract(b)
			if errors.Is(err, ErrNoManifest) {
				if !exp.Failed() {
					t.Fatal("no C2PA chunk, but the oracle read a manifest store")
				}
				stripped, err := Strip(b)
				if err != nil || !bytes.Equal(stripped, b) {
					t.Errorf("Strip of a file without a store changed it (%v)", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if exp.Failed() {
				t.Fatalf("Extract succeeded, oracle failed: %s", exp.C2patoolError)
			}
			// Same manifests as the oracle.
			var want []string
			for label := range exp.Manifests {
				want = append(want, label)
			}
			slices.Sort(want)
			if got := manifestLabels(st.Root); !slices.Equal(got, want) {
				t.Errorf("manifests %v, oracle %v", got, want)
			}
			// c2patool's exclusion is the chunk header and data, not the pad.
			var am struct {
				AssertionStore struct {
					HashData struct {
						Exclusions []struct{ Start, Length int } `json:"exclusions"`
					} `json:"c2pa.hash.data"`
				} `json:"assertion_store"`
			}
			if err := json.Unmarshal(exp.Manifests[exp.ActiveManifest], &am); err == nil && len(am.AssertionStore.HashData.Exclusions) == 1 {
				ex := am.AssertionStore.HashData.Exclusions[0]
				if ex.Start != st.Chunk.Offset || ex.Length != st.Chunk.ExclusionLength() {
					t.Errorf("c2patool excluded [%d, +%d), chunk is at %d, ExclusionLength %d", ex.Start, ex.Length, st.Chunk.Offset, st.Chunk.ExclusionLength())
				}
			}
			// The chunk is last in the RIFF, where c2pa-rs puts it.
			chunks, _ := Chunks(b)
			if chunks[len(chunks)-1].Offset != st.Chunk.Offset {
				t.Error("the C2PA chunk is not the last chunk")
			}
			stripped, err := Strip(b)
			if err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint32(stripped[4:8])+8 != uint32(len(stripped)) {
				t.Error("Strip left a wrong RIFF size")
			}
			again, c, err := Insert(stripped, st.JUMBF)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, b) || c != st.Chunk {
				t.Error("Insert(Strip(f), store) differs from f")
			}
			signed++
		})
	}
	if signed < 7 {
		t.Errorf("round-tripped %d signed WebP fixtures, want at least 7", signed)
	}
}

// riff builds a WebP from chunks (FourCC, data), padding odd ones.
func riff(chunks ...[2]string) []byte {
	b := []byte("RIFF\x00\x00\x00\x00WEBP")
	for _, c := range chunks {
		b = appendChunk(b, c[0], []byte(c[1]))
	}
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)-8))
	return b
}

func TestInsertPadAndExclusion(t *testing.T) {
	base := riff([2]string{"VP8L", "\x2f\x00\x00\x00\x00ab"}) // 7 bytes, odd: padded
	for _, n := range []int{10, 11} {
		store := bytes.Repeat([]byte{0xAB}, n)
		out, c, err := Insert(base, store)
		if err != nil {
			t.Fatal(err)
		}
		if c.Offset%2 != 0 || c.Offset != len(base) || c.Length != n || c.ExclusionLength() != 8+n || c.Size() != InsertedSize(n) {
			t.Errorf("n=%d: chunk %+v", n, c)
		}
		if len(out) != len(base)+InsertedSize(n) || binary.LittleEndian.Uint32(out[4:8]) != uint32(len(out)-8) {
			t.Errorf("n=%d: %d bytes, RIFF size %d", n, len(out), binary.LittleEndian.Uint32(out[4:8]))
		}
		if n%2 == 1 && out[len(out)-1] != 0 {
			t.Error("odd store not padded")
		}
		if !bytes.Equal(c.Data(out), store) {
			t.Error("store bytes differ")
		}
		if back, _ := Strip(out); !bytes.Equal(back, base) {
			t.Errorf("n=%d: Strip(Insert) differs", n)
		}
		// WriteStore stays inside the data.
		if err := WriteStore(out, c, n-2, []byte{1, 2}); err != nil || !bytes.Equal(c.Data(out)[n-2:], []byte{1, 2}) {
			t.Errorf("WriteStore: %v", err)
		}
		if err := WriteStore(out, c, n-1, []byte{1, 2}); !errors.Is(err, ErrOutOfRange) {
			t.Errorf("WriteStore past the store: %v", err)
		}
	}
	// The last chunk's missing pad byte is restored before the new chunk.
	unpadded := bytes.Clone(base[:len(base)-1])
	binary.LittleEndian.PutUint32(unpadded[4:8], uint32(len(unpadded)-8))
	if _, err := Chunks(unpadded); err != nil {
		t.Fatalf("an unpadded last chunk should read: %v", err)
	}
	out, c, err := Insert(unpadded, []byte("xy"))
	if err != nil || c.Offset != len(base) || out[len(unpadded)] != 0 {
		t.Errorf("unpadded: %v, chunk %+v", err, c)
	}
	// Bytes after the RIFF are kept after it.
	trailing := append(bytes.Clone(base), "trailer"...)
	out, _, err = Insert(trailing, []byte("xy"))
	if err != nil || !bytes.HasSuffix(out, []byte("trailer")) || binary.LittleEndian.Uint32(out[4:8]) != uint32(len(out)-8-len("trailer")) {
		t.Errorf("trailing data: %v", err)
	}
	if back, _ := Strip(out); !bytes.Equal(back, trailing) {
		t.Error("Strip with trailing data differs")
	}
}

func TestErrors(t *testing.T) {
	ok := riff([2]string{"VP8L", "\x2f\x00\x00\x00\x00"})
	two := riff([2]string{"VP8L", "x"}, [2]string{"C2PA", "a"}, [2]string{"C2PA", "b"})
	tooBig := bytes.Clone(ok)
	binary.LittleEndian.PutUint32(tooBig[4:8], 1000)
	badChunk := bytes.Clone(ok)
	binary.LittleEndian.PutUint32(badChunk[16:20], 1000)
	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrNotWebP},
		{"PNG", []byte("\x89PNG\r\n\x1a\n...."), ErrNotWebP},
		{"RIFF but WAVE", []byte("RIFF\x04\x00\x00\x00WAVE"), ErrNotWebP},
		{"RIFF size past the end", tooBig, ErrTruncated},
		{"chunk past the end", badChunk, ErrTruncated},
		{"half a chunk header", append(riff(), "VP8"...), ErrTruncated},
		{"two stores", two, ErrMultipleStores},
		{"no store", ok, ErrNoManifest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			if tc.name == "half a chunk header" {
				binary.LittleEndian.PutUint32(in[4:8], uint32(len(in)-8))
			}
			if _, err := Extract(in); !errors.Is(err, tc.want) {
				t.Errorf("Extract: %v, want %v", err, tc.want)
			}
		})
	}
	if _, _, err := Insert(two, []byte("x")); !errors.Is(err, ErrMultipleStores) {
		t.Errorf("Insert into a file with two stores: %v", err)
	}
	withStore, _, _ := Insert(ok, []byte("x"))
	if _, _, err := Insert(withStore, []byte("y")); !errors.Is(err, ErrHasManifest) {
		t.Errorf("Insert into a signed file: %v", err)
	}
}

func fuzzSeeds(f *testing.F) {
	all, _ := fixtures.List()
	for _, fx := range all {
		if fx.Format == "webp" {
			if b, err := os.ReadFile(fx.Path); err == nil && len(b) < 64<<10 {
				f.Add(b)
			}
		}
	}
	f.Add(riff([2]string{"VP8X", "\x00\x00\x00\x00\x01\x00\x00\x01\x00\x00"}, [2]string{"VP8 ", "abc"}))
	f.Add([]byte("RIFF\xff\xff\xff\xffWEBP"))
}

// FuzzStripInsert: Chunks, Extract, Strip, Insert and SetXMP never panic,
// and on any file Chunks accepts, Strip(Insert(Strip(b), s)) == Strip(b).
func FuzzStripInsert(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		Extract(b)
		XMP(b)
		SetXMP(b, []byte("<x/>"))
		if _, err := Chunks(b); err != nil {
			return
		}
		s, err := Strip(b)
		if err != nil {
			return // two stores
		}
		out, c, err := Insert(s, []byte("store"))
		if err != nil {
			t.Fatalf("Insert after Strip: %v", err)
		}
		if !bytes.Equal(c.Data(out), []byte("store")) {
			t.Fatal("inserted store not where Insert says")
		}
		back, err := Strip(out)
		if err != nil {
			t.Fatal(err)
		}
		// Insert may add the last chunk's missing pad byte; nothing else.
		if !bytes.Equal(back, s) && !(len(back) == len(s)+1 && bytes.Equal(back[12:len(s)], s[12:]) && back[len(back)-1] == 0) {
			t.Fatal("Strip(Insert(s)) differs from s")
		}
	})
}
