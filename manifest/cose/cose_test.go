package cose

import (
	"errors"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/fxamacker/cbor/v2"
)

func enc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbormode.Enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func message(t *testing.T, protected map[any]any, unprotected map[any]any, tagged bool) []byte {
	t.Helper()
	body := []any{enc(t, protected), unprotected, nil, make([]byte, 64)}
	if tagged {
		return enc(t, cbor.Tag{Number: tagSign1, Content: body})
	}
	return enc(t, body)
}

func TestDecode(t *testing.T) {
	cert := []byte{0x30, 0x01}
	tst := map[string]any{"tstTokens": []any{map[string]any{"val": []byte{1, 2}}}}
	for _, tagged := range []bool{true, false} {
		b := message(t, map[any]any{HeaderAlg: AlgES256, HeaderX5Chain: []any{cert, cert}},
			map[any]any{HeaderSigTst2: tst, "pad": make([]byte, 10)}, tagged)
		s, err := Decode(b)
		if err != nil {
			t.Fatalf("tagged=%v: %v", tagged, err)
		}
		if s.Alg != AlgES256 || len(s.X5Chain) != 2 || len(s.Signature) != 64 || s.Payload != nil {
			t.Errorf("decoded %+v", s)
		}
		if len(s.Timestamps) != 1 || s.Timestamps[0].Version != 2 || len(s.Timestamps[0].Token) != 2 {
			t.Errorf("timestamps %+v", s.Timestamps)
		}
	}

	// Single-certificate x5chain in the unprotected header (C2PA 1.x style).
	s, err := Decode(message(t, map[any]any{HeaderAlg: AlgES256}, map[any]any{HeaderX5Chain: cert}, true))
	if err != nil || len(s.X5Chain) != 1 {
		t.Errorf("unprotected x5chain: %v, %+v", err, s)
	}
}

func TestDecodeErrors(t *testing.T) {
	cert := []byte{0x30}
	ok := map[any]any{HeaderAlg: AlgES256, HeaderX5Chain: cert}
	tests := map[string][]byte{
		"not CBOR":          {0xFF},
		"wrong tag":         enc(t, cbor.Tag{Number: 98, Content: []any{}}),
		"short array":       enc(t, []any{[]byte{0xA0}}),
		"empty protected":   enc(t, []any{[]byte{}, map[any]any{}, nil, []byte{1}}),
		"protected not map": enc(t, []any{[]byte{0x01}, map[any]any{}, nil, []byte{1}}),
		"no alg":            message(t, map[any]any{HeaderX5Chain: cert}, nil, true),
		"text alg":          message(t, map[any]any{HeaderAlg: "ES256", HeaderX5Chain: cert}, nil, true),
		"no x5chain":        message(t, map[any]any{HeaderAlg: AlgES256}, nil, true),
		"x5chain int":       message(t, map[any]any{HeaderAlg: AlgES256, HeaderX5Chain: 5}, nil, true),
		"x5chain bad entry": message(t, map[any]any{HeaderAlg: AlgES256, HeaderX5Chain: []any{"x"}}, nil, true),
		"bad sigTst2":       message(t, ok, map[any]any{HeaderSigTst2: "x"}, true),
		"sigTst2 no val":    message(t, ok, map[any]any{HeaderSigTst2: map[string]any{"tstTokens": []any{map[string]any{}}}}, true),
	}
	for name, b := range tests {
		if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error %v, want ErrMalformed", name, err)
		}
	}
}

func TestAlgName(t *testing.T) {
	if AlgName(AlgES256) != "es256" || AlgName(12345) != "" {
		t.Error("AlgName")
	}
}
