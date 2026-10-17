package assertion

import (
	"errors"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
)

func superbox(label string, content ...*jumbf.Box) *jumbf.Box {
	return &jumbf.Box{Type: jumbf.TypeSuperbox, Children: append([]*jumbf.Box{{
		Type:        jumbf.TypeDescription,
		Description: &jumbf.Description{Toggles: jumbf.ToggleLabel, Label: label},
	}}, content...)}
}

func cborBox(t *testing.T, v any) *jumbf.Box {
	t.Helper()
	b, err := cbormode.Enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return &jumbf.Box{Type: "cbor", Payload: b}
}

func TestBaseLabel(t *testing.T) {
	for in, want := range map[string]string{
		"c2pa.actions":         "c2pa.actions",
		"c2pa.actions.v2__1":   "c2pa.actions.v2",
		"c2pa.hash.data__12":   "c2pa.hash.data",
		"c2pa.thumbnail.claim": "c2pa.thumbnail.claim",
		"x__y":                 "x__y",
	} {
		if got := BaseLabel(in); got != want {
			t.Errorf("BaseLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecode(t *testing.T) {
	bfdb := &jumbf.Box{Type: "bfdb", Payload: []byte("\x00image/png\x00")}
	bidb := &jumbf.Box{Type: "bidb", Payload: []byte{1, 2, 3}}

	a := Decode(superbox("c2pa.hash.data__1", cborBox(t, map[string]any{
		"exclusions": []any{map[string]any{"start": 2, "length": 100}},
		"alg":        "sha256", "hash": []byte{9}, "pad": []byte{0, 0},
	})))
	if dh, ok := a.Value.(*DataHash); a.Err != nil || !ok || dh.Exclusions[0] != (Exclusion{2, 100}) || len(dh.Pad) != 2 {
		t.Errorf("data hash: %+v, err %v", a.Value, a.Err)
	}

	a = Decode(superbox("c2pa.actions", cborBox(t, map[string]any{
		"actions": []any{map[string]any{"action": "c2pa.edited", "softwareAgent": "v1 string agent"}},
	})))
	if act, ok := a.Value.(*Actions); a.Err != nil || !ok || act.Actions[0].SoftwareAgent != "v1 string agent" {
		t.Errorf("v1 actions: %+v, err %v", a.Value, a.Err)
	}

	a = Decode(superbox("c2pa.thumbnail.claim.png", bfdb, bidb))
	if th, ok := a.Value.(*Thumbnail); a.Err != nil || !ok || th.Format != "image/png" || len(th.Data) != 3 {
		t.Errorf("thumbnail: %+v, err %v", a.Value, a.Err)
	}

	a = Decode(superbox(LabelCreativeWork, cborBox(t, map[string]any{"@type": "CreativeWork"})))
	if cw, ok := a.Value.(CreativeWork); a.Err != nil || !ok || cw["@type"] != "CreativeWork" {
		t.Errorf("CBOR CreativeWork: %+v, err %v", a.Value, a.Err)
	}

	a = Decode(superbox("c2pa.ingredient.v3", cborBox(t, map[string]any{"x": 1})))
	if a.Value != nil || a.Err != nil {
		t.Errorf("unknown label decoded: %+v, err %v", a.Value, a.Err)
	}
}

func TestDecodeMalformed(t *testing.T) {
	tests := map[string]*jumbf.Box{
		"hash.data negative start": superbox(LabelDataHash, cborBox(t, map[string]any{
			"exclusions": []any{map[string]any{"start": -1, "length": 1}}, "hash": []byte{1}, "pad": []byte{}})),
		"hash.data as json":      superbox(LabelDataHash, &jumbf.Box{Type: "json", Payload: []byte("{}")}),
		"actions not a map":      superbox(LabelActionsV2, cborBox(t, []int{1})),
		"actions bad CBOR":       superbox(LabelActionsV2, &jumbf.Box{Type: "cbor", Payload: []byte{0xFF}}),
		"actions no content":     superbox(LabelActionsV2),
		"creativework bad json":  superbox(LabelCreativeWork, &jumbf.Box{Type: "json", Payload: []byte("{")}),
		"thumbnail missing bidb": superbox(LabelThumbnailClaim, &jumbf.Box{Type: "bfdb", Payload: []byte("\x00image/jpeg\x00")}),
		"thumbnail unterminated": superbox(LabelThumbnailClaim, &jumbf.Box{Type: "bfdb", Payload: []byte("\x00image/jpeg")}, &jumbf.Box{Type: "bidb"}),
		"duplicate key":          superbox(LabelDataHash, &jumbf.Box{Type: "cbor", Payload: []byte{0xA2, 0x61, 'a', 1, 0x61, 'a', 2}}),
	}
	for name, box := range tests {
		a := Decode(box)
		if !errors.Is(a.Err, ErrMalformed) || a.Value != nil {
			t.Errorf("%s: value %+v, err %v; want ErrMalformed", name, a.Value, a.Err)
		}
	}
}
