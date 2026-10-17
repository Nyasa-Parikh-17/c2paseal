package jumbf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// Hand-built encodings, written independently of Serialize.

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func box(typ string, payload ...[]byte) []byte {
	p := cat(payload...)
	return cat(binary.BigEndian.AppendUint32(nil, uint32(8+len(p))), []byte(typ), p)
}

func extBox(typ string, payload ...[]byte) []byte {
	p := cat(payload...)
	return cat([]byte{0, 0, 0, 1}, []byte(typ), binary.BigEndian.AppendUint64(nil, uint64(16+len(p))), p)
}

func toEndBox(typ string, payload ...[]byte) []byte {
	return cat([]byte{0, 0, 0, 0}, []byte(typ), cat(payload...))
}

var (
	uuidC2PA = UUID{0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}
	uuidCBOR = UUID{0x63, 0x62, 0x6F, 0x72, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}
)

// jumd builds a description box with a label and the requestable toggle.
func jumd(u UUID, label string) []byte {
	return box("jumd", u[:], []byte{ToggleRequestable | ToggleLabel}, []byte(label), []byte{0})
}

func super(u UUID, label string, children ...[]byte) []byte {
	return box("jumb", jumd(u, label), cat(children...))
}

// manifestStore is shaped like a C2PA store: store / manifest / assertions.
func manifestStore() []byte {
	return super(uuidC2PA, "c2pa",
		super(uuidC2PA, "urn:c2pa:1234",
			super(uuidC2PA, "c2pa.assertions",
				super(uuidCBOR, "c2pa.hash.data", box("cbor", []byte{0xA1, 0x63, 'a', 'l', 'g', 0x66, 's', 'h', 'a', '2', '5', '6'})),
				super(uuidCBOR, "c2pa.actions.v2", box("cbor", []byte{0xA0})),
			),
			super(uuidCBOR, "c2pa.claim.v2", box("cbor", []byte{0xA0})),
			super(uuidCBOR, "c2pa.signature", box("cbor", bytes.Repeat([]byte{0x5A}, 64))),
		),
	)
}

var roundTrips = map[string][]byte{
	"content box":     box("cbor", []byte{1, 2, 3}),
	"empty content":   box("json"),
	"manifest store":  manifestStore(),
	"extended length": extBox("jumb", jumd(uuidCBOR, "x"), extBox("bfdb", []byte("payload"))),
	"to end":          toEndBox("jumb", jumd(uuidCBOR, "x"), box("uuid", uuidC2PA[:]), toEndBox("bidb", []byte("tail"))),
	"jumd all fields": box("jumb",
		box("jumd", uuidCBOR[:], []byte{0x1F}, []byte("all\x00"),
			[]byte{0, 0, 0, 42}, bytes.Repeat([]byte{0xEE}, 32), box("c2sh", []byte("salt")), []byte("extra")),
		box("cbor", []byte{0xF6})),
	"jumd no label": box("jumb", box("jumd", uuidCBOR[:], []byte{0}), box("cbor")),
	"empty label":   super(uuidCBOR, "", box("cbor")),
	"unknown types": super(uuidC2PA, "c2pa", box("c2sh", make([]byte, 16)), box("free", []byte("x"))),
}

func TestRoundTrip(t *testing.T) {
	for name, in := range roundTrips {
		t.Run(name, func(t *testing.T) {
			b, err := Parse(in)
			if err != nil {
				t.Fatal(err)
			}
			if out := Serialize(b); !bytes.Equal(out, in) {
				t.Fatalf("Serialize(Parse(b)) differs:\n got %x\nwant %x", out, in)
			}
			if !bytes.Equal(b.Raw, in) || b.Offset != 0 || b.Size() != len(in) {
				t.Errorf("Raw/Offset/Size not kept: offset %d size %d", b.Offset, b.Size())
			}
		})
	}
}

func TestParseFields(t *testing.T) {
	in := manifestStore()
	root, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if root.Label() != "c2pa" || root.Desc().ContentType != uuidC2PA {
		t.Errorf("root label %q type %v", root.Label(), root.Desc().ContentType)
	}
	sig := root.Find("c2pa/urn:c2pa:1234/c2pa.signature")
	if sig == nil {
		t.Fatal("signature box not found")
	}
	content := sig.Contents()[0]
	if content.Type != "cbor" || len(content.Payload) != 64 {
		t.Errorf("signature content: type %q, %d bytes", content.Type, len(content.Payload))
	}
	// Every box's Raw must be the slice of the input at its Offset.
	var walk func(*Box)
	walk = func(b *Box) {
		if !bytes.Equal(in[b.Offset:b.Offset+len(b.Raw)], b.Raw) {
			t.Errorf("%s box at %d: Raw does not match input", b.Type, b.Offset)
		}
		for _, c := range b.Children {
			walk(c)
		}
	}
	walk(root)

	d := mustParse(t, roundTrips["jumd all fields"]).Desc()
	if d.Label != "all" || d.ID != 42 || len(d.Hash) != 32 || d.Private == nil ||
		d.Private.Type != "c2sh" || string(d.Extra) != "extra" {
		t.Errorf("description fields: %+v", d)
	}
}

func mustParse(t *testing.T, b []byte) *Box {
	t.Helper()
	box, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func TestFind(t *testing.T) {
	root := mustParse(t, manifestStore())
	tests := []struct {
		path string
		want string // label of result, "" for nil
	}{
		{"c2pa", "c2pa"},
		{"c2pa/urn:c2pa:1234/c2pa.assertions/c2pa.hash.data", "c2pa.hash.data"},
		{"c2pa/urn:c2pa:1234/c2pa.assertions/c2pa.actions.v2", "c2pa.actions.v2"},
		{"c2pa/urn:c2pa:1234/c2pa.assertions/missing", ""},
		{"other/urn:c2pa:1234", ""},
		{"", ""},
		{"c2pa/", ""},
	}
	for _, tt := range tests {
		got := root.Find(tt.path)
		if (got == nil) != (tt.want == "") || (got != nil && got.Label() != tt.want) {
			t.Errorf("Find(%q) = %v, want label %q", tt.path, got, tt.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	deep := box("cbor")
	for range maxDepth + 1 {
		deep = super(uuidCBOR, "d", deep)
	}
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTopLevel},
		{"short header", []byte{0, 0, 0, 8, 'j'}, ErrTruncated},
		{"LBox below 8", []byte{0, 0, 0, 7, 'c', 'b', 'o', 'r'}, ErrBadLength},
		{"XLBox below 16", cat([]byte{0, 0, 0, 1}, []byte("cbor"), make([]byte, 7), []byte{15}), ErrBadLength},
		{"XLBox header cut", cat([]byte{0, 0, 0, 1}, []byte("cbor"), []byte{0, 0}), ErrTruncated},
		{"length past end", cat([]byte{0, 0, 0, 99}, []byte("cbor")), ErrTruncated},
		{"huge XLBox", cat([]byte{0, 0, 0, 1}, []byte("cbor"), bytes.Repeat([]byte{0xFF}, 8)), ErrTruncated},
		{"empty superbox", box("jumb"), ErrNoDescription},
		{"superbox without jumd", box("jumb", box("cbor")), ErrNoDescription},
		{"short jumd", box("jumb", box("jumd", make([]byte, 16))), ErrTruncated},
		{"unterminated label", box("jumb", box("jumd", uuidCBOR[:], []byte{ToggleLabel}, []byte("abc"))), ErrTruncated},
		{"short ID", box("jumb", box("jumd", uuidCBOR[:], []byte{ToggleID}, []byte{1, 2})), ErrTruncated},
		{"short hash", box("jumb", box("jumd", uuidCBOR[:], []byte{ToggleHash}, make([]byte, 31))), ErrTruncated},
		{"bad private box", box("jumb", box("jumd", uuidCBOR[:], []byte{TogglePrivate}, []byte{0, 0, 0, 3})), ErrTruncated},
		{"bad child length", super(uuidC2PA, "c2pa", cat([]byte{0, 0, 0, 2}, []byte("cbor"))), ErrBadLength},
		{"two top-level boxes", cat(box("cbor"), box("cbor")), ErrTopLevel},
		{"trailing garbage", cat(manifestStore(), []byte{0}), ErrTruncated},
		{"too deep", deep, ErrTooDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "jumbf: ") {
				t.Errorf("error lacks package prefix: %v", err)
			}
		})
	}
}

func TestErrorOffset(t *testing.T) {
	in := super(uuidC2PA, "c2pa", box("cbor"), cat([]byte{0, 0, 0, 2}, []byte("cbor")))
	_, err := Parse(in)
	want := len(in) - 8
	if err == nil || !strings.Contains(err.Error(), "offset "+strconv.Itoa(want)+":") {
		t.Errorf("error %v does not name offset %d", err, want)
	}
}

func TestSerializeBuilt(t *testing.T) {
	root := &Box{Type: TypeSuperbox, Children: []*Box{
		{Type: TypeDescription, Description: &Description{ContentType: uuidC2PA, Toggles: ToggleRequestable | ToggleLabel, Label: "c2pa"}},
		{Type: TypeSuperbox, Children: []*Box{
			{Type: TypeDescription, Description: &Description{ContentType: uuidCBOR, Toggles: ToggleRequestable | ToggleLabel, Label: "c2pa.claim.v2"}},
			{Type: "cbor", Payload: []byte{0xA0}},
		}},
	}}
	want := super(uuidC2PA, "c2pa", super(uuidCBOR, "c2pa.claim.v2", box("cbor", []byte{0xA0})))
	if got := Serialize(root); !bytes.Equal(got, want) {
		t.Fatalf("Serialize built tree:\n got %x\nwant %x", got, want)
	}
	if root.Size() != len(want) {
		t.Errorf("Size = %d, want %d", root.Size(), len(want))
	}
}

// pngStore returns the payload of the caBX chunk in a PNG, or nil.
func pngStore(b []byte) []byte {
	for i := 8; i+12 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[i:]))
		if i+12+n > len(b) {
			return nil
		}
		if string(b[i+4:i+8]) == "caBX" {
			return b[i+8 : i+8+n]
		}
		i += 12 + n
	}
	return nil
}

// TestFixtureStores round-trips the real manifest stores in the signed PNG
// fixtures (PNG keeps the store in one chunk, so no container parser is needed).
func TestFixtureStores(t *testing.T) {
	fs, err := fixtures.ListKind(fixtures.Signed)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fs {
		if f.Format != "png" {
			continue
		}
		n++
		t.Run(f.Name, func(t *testing.T) {
			raw, err := os.ReadFile(f.Path)
			if err != nil {
				t.Fatal(err)
			}
			store := pngStore(raw)
			if store == nil {
				t.Fatal("no caBX chunk")
			}
			root := mustParse(t, store)
			if !bytes.Equal(Serialize(root), store) {
				t.Fatal("Serialize(Parse(store)) differs from store")
			}
			exp, err := f.Expected()
			if err != nil {
				t.Fatal(err)
			}
			path := "c2pa/" + exp.ActiveManifest + "/c2pa.assertions/c2pa.hash.data"
			if root.Find(path) == nil {
				t.Errorf("Find(%q) = nil", path)
			}
		})
	}
	if n == 0 {
		t.Fatal("no signed PNG fixtures")
	}
}

func FuzzParse(f *testing.F) {
	for _, b := range roundTrips {
		f.Add(b)
	}
	// Real stores as seeds, skipping big ones: the fuzzer slows to a crawl
	// mutating inputs of hundreds of kilobytes.
	if fs, err := fixtures.ListKind(fixtures.Signed); err == nil {
		for _, fx := range fs {
			raw, err := os.ReadFile(fx.Path)
			if s := pngStore(raw); err == nil && s != nil && len(s) <= 64<<10 {
				f.Add(s)
			}
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if boxes, err := ParseAll(in); err == nil {
			var out []byte
			for _, b := range boxes {
				out = Append(out, b)
			}
			if !bytes.Equal(out, in) {
				t.Fatalf("ParseAll round trip differs:\n got %x\nwant %x", out, in)
			}
		}
	})
}
