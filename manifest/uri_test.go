package manifest

import (
	"errors"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
)

// TestHashChecks: every assertion reference matches in every fixture except
// assertion-flip.jpg, where exactly the actions assertion mismatches.
func TestHashChecks(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	sawFlip := false
	for _, f := range all {
		exp, err := f.Expected()
		if err != nil {
			t.Fatal(err)
		}
		if exp.Failed() {
			continue
		}
		root, err := extract(f)
		if err != nil {
			t.Fatal(err)
		}
		ms, err := DecodeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			if s := m.Signature; m.SignatureErr != nil || s.Alg != cose.AlgES256 || len(s.X5Chain) != 2 || len(s.Signature) != 64 {
				t.Errorf("%s: signature %v, err %v", f, s, m.SignatureErr)
			}
			if len(m.HashChecks) != len(m.Claim.Assertions()) {
				t.Errorf("%s: %d checks for %d references", f, len(m.HashChecks), len(m.Claim.Assertions()))
			}
			for _, c := range m.HashChecks {
				if c.Err != nil {
					t.Errorf("%s: %s: %v", f, c.Ref.URL, c.Err)
				}
				wantMatch := !(f.Name == "assertion-flip.jpg" && c.Ref.URL == "self#jumbf=c2pa.assertions/c2pa.actions.v2")
				if c.Match != wantMatch {
					t.Errorf("%s: %s: match = %v, want %v", f, c.Ref.URL, c.Match, wantMatch)
				}
				if !wantMatch {
					sawFlip = true
				}
			}
		}
	}
	if !sawFlip {
		t.Error("assertion-flip.jpg mismatch not seen")
	}
}

func TestResolve(t *testing.T) {
	leaf := superbox("c2pa.hash.data", &jumbf.Box{Type: "cbor", Payload: []byte{0xA0}})
	sig := superbox(LabelSignature)
	m := superbox("urn:c2pa:1", superbox(LabelAssertions, leaf), sig)
	root := superbox(LabelStore, m)

	tests := []struct {
		uri  string
		want *jumbf.Box
		err  error
	}{
		{"self#jumbf=c2pa.assertions/c2pa.hash.data", leaf, nil},
		{"self#jumbf=/c2pa/urn:c2pa:1/c2pa.signature", sig, nil},
		{"self#jumbf=/c2pa/urn:c2pa:1/c2pa.assertions/c2pa.hash.data", leaf, nil},
		{"self#jumbf=c2pa.assertions/missing", nil, ErrUnresolved},
		{"self#jumbf=/other/urn:c2pa:1", nil, ErrUnresolved},
		{"self#jumbf=", nil, ErrBadURI},
		{"https://example.com/x", nil, ErrBadURI},
	}
	for _, tt := range tests {
		got, err := Resolve(root, m, tt.uri)
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("Resolve(%q) = %v, %v; want %v, %v", tt.uri, got, err, tt.want, tt.err)
		}
	}
}

func TestHashBox(t *testing.T) {
	b := superbox("x", &jumbf.Box{Type: "cbor", Payload: []byte{1, 2, 3}})
	for _, alg := range []string{"sha256", "sha384", "sha512"} {
		parsed, err := jumbf.Parse(jumbf.Serialize(b))
		if err != nil {
			t.Fatal(err)
		}
		h1, err1 := HashBox(alg, b)
		h2, err2 := HashBox(alg, parsed)
		if err := errors.Join(err1, err2); err != nil || string(h1) != string(h2) {
			t.Errorf("%s: built and parsed boxes hash differently (%v)", alg, err)
		}
	}
	if _, err := HashBox("md5", b); !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("md5: %v, want ErrUnsupportedAlg", err)
	}
}
