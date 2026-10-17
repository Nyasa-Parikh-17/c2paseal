package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
)

func extract(f fixtures.Fixture) (*jumbf.Box, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	if f.Format == "png" {
		st, err := png.Extract(b)
		if err != nil {
			return nil, err
		}
		return st.Root, nil
	}
	st, err := jpeg.Extract(b)
	if err != nil {
		return nil, err
	}
	return st.Root, nil
}

// normalize round-trips v through JSON so it compares with oracle output.
func normalize(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// oracleManifest is the per-manifest part of c2patool --detailed output.
type oracleManifest struct {
	Claim          map[string]any             `json:"claim"`
	AssertionStore map[string]json.RawMessage `json:"assertion_store"`
}

// TestFixtures decodes every manifest in every readable fixture and compares
// the claim and in-scope assertions with the c2patool oracle.
func TestFixtures(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range all {
		exp, err := f.Expected()
		if err != nil {
			t.Fatal(err)
		}
		if exp.Failed() {
			continue
		}
		t.Run(f.String(), func(t *testing.T) {
			root, err := extract(f)
			if err != nil {
				t.Fatal(err)
			}
			ms, err := DecodeStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if got := ms[len(ms)-1].Label; got != exp.ActiveManifest {
				t.Errorf("last manifest %q, oracle active manifest %q", got, exp.ActiveManifest)
			}
			if len(ms) != len(exp.Manifests) {
				t.Fatalf("%d manifests, oracle has %d", len(ms), len(exp.Manifests))
			}
			for _, m := range ms {
				raw, ok := exp.Manifests[m.Label]
				if !ok {
					t.Errorf("manifest %q not in oracle", m.Label)
					continue
				}
				var want oracleManifest
				if err := json.Unmarshal(raw, &want); err != nil {
					t.Fatal(err)
				}
				checkClaim(t, m, want.Claim)
				checkAssertions(t, m, want.AssertionStore)
				checked++
			}
		})
	}
	if checked < 13 {
		t.Errorf("only %d manifests checked", checked)
	}
}

func checkClaim(t *testing.T, m *Manifest, want map[string]any) {
	t.Helper()
	got := normalize(t, m.Claim).(map[string]any)
	for _, k := range []string{"instanceID", "claim_generator_info", "signature", "created_assertions", "alg"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: decoded claim lacks %q", m.Label, k)
		}
	}
	// Every field we decode must equal the oracle's. The oracle has extra
	// computed keys (claim_version) that are not claim fields.
	for k, v := range got {
		if !reflect.DeepEqual(v, want[k]) {
			t.Errorf("%s: claim %q = %v, oracle %v", m.Label, k, v, want[k])
		}
	}
	if m.Claim.ClaimGeneratorInfo.Name() != "c2paseal-fixtures" {
		t.Errorf("%s: generator name %q", m.Label, m.Claim.ClaimGeneratorInfo.Name())
	}
}

func checkAssertions(t *testing.T, m *Manifest, want map[string]json.RawMessage) {
	t.Helper()
	var labels, wantLabels []string
	for _, a := range m.Assertions {
		labels = append(labels, a.Label)
	}
	for l := range want {
		wantLabels = append(wantLabels, l)
	}
	slices.Sort(labels)
	slices.Sort(wantLabels)
	if !slices.Equal(labels, wantLabels) {
		t.Errorf("%s: assertion labels %q, oracle %q", m.Label, labels, wantLabels)
	}
	for _, a := range m.Assertions {
		if a.Err != nil {
			t.Errorf("%s: %v", m.Label, a.Err)
			continue
		}
		switch v := a.Value.(type) {
		case nil:
			// Out of scope (e.g. c2pa.ingredient.v3): kept raw.
		case *assertion.Thumbnail:
			if w := fmt.Sprintf("%q", fmt.Sprintf("<omitted> len = %d", len(v.Data))); string(want[a.Label]) != w {
				t.Errorf("%s: %s: %d bytes, oracle %s", m.Label, a.Label, len(v.Data), want[a.Label])
			}
			if v.Format != "image/jpeg" {
				t.Errorf("%s: %s format %q", m.Label, a.Label, v.Format)
			}
		default:
			var w any
			if err := json.Unmarshal(want[a.Label], &w); err != nil {
				t.Fatal(err)
			}
			if got := normalize(t, v); !reflect.DeepEqual(got, w) {
				t.Errorf("%s: %s =\n %v\noracle\n %v", m.Label, a.Label, got, w)
			}
		}
	}
	if m.Assertion(assertion.LabelDataHash) == nil {
		t.Errorf("%s: no c2pa.hash.data", m.Label)
	}
}

// TestRawKept: the decoded claim keeps the exact bytes from the file.
func TestRawKept(t *testing.T) {
	fs, err := fixtures.ListKind(fixtures.Signed)
	if err != nil {
		t.Fatal(err)
	}
	root, err := extract(fs[0])
	if err != nil {
		t.Fatal(err)
	}
	ms, err := DecodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	m := ms[0]
	if want := m.ClaimBox.Contents()[0].Payload; &m.Claim.Raw[0] != &want[0] || len(m.Claim.Raw) != len(want) {
		t.Error("Claim.Raw is not the original claim bytes")
	}
}

func enc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbormode.Enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validClaim() map[string]any {
	return map[string]any{
		"instanceID":           "xmp:iid:1",
		"claim_generator_info": map[string]any{"name": "test"},
		"signature":            "self#jumbf=/c2pa/urn:c2pa:1/c2pa.signature",
		"created_assertions":   []any{map[string]any{"url": "self#jumbf=c2pa.assertions/c2pa.hash.data", "hash": []byte{1}}},
	}
}

func TestDecodeClaimErrors(t *testing.T) {
	without := func(k string) []byte {
		c := validClaim()
		delete(c, k)
		return enc(t, c)
	}
	badRef := validClaim()
	badRef["created_assertions"] = []any{map[string]any{"url": "x"}}
	wrongType := validClaim()
	wrongType["instanceID"] = 7

	tests := map[string][]byte{
		"not CBOR":         {0xFF},
		"not a map":        enc(t, []int{1}),
		"no instanceID":    without("instanceID"),
		"no generator":     without("claim_generator_info"),
		"no signature":     without("signature"),
		"no assertions":    without("created_assertions"),
		"ref without hash": enc(t, badRef),
		"wrong type":       enc(t, wrongType),
		"duplicate key":    {0xA2, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
	}
	for name, b := range tests {
		if _, err := DecodeClaim(b); !errors.Is(err, ErrMalformedClaim) {
			t.Errorf("%s: error %v, want ErrMalformedClaim", name, err)
		}
	}
	if _, err := DecodeClaim(enc(t, validClaim())); err != nil {
		t.Errorf("valid claim: %v", err)
	}
}

func TestClaimEncodeRoundTrip(t *testing.T) {
	c, err := DecodeClaim(enc(t, validClaim()))
	if err != nil {
		t.Fatal(err)
	}
	c.Title = "title"
	c.Alg = "sha256"
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := c.Encode()
	if err != nil || string(b) != string(b2) {
		t.Fatal("encoding is not deterministic")
	}
	back, err := DecodeClaim(b)
	if err != nil {
		t.Fatal(err)
	}
	back.Raw, c.Raw = nil, nil
	if !reflect.DeepEqual(back, c) {
		t.Errorf("decode(encode(c)) = %+v, want %+v", back, c)
	}
	// Core deterministic order sorts keys by encoded bytes, so the shortest
	// key, "alg", comes right after the 6-entry map header.
	if want := []byte{0xA6, 0x63, 'a', 'l', 'g'}; string(b[:5]) != string(want) {
		t.Errorf("encoding starts % x, want % x", b[:5], want)
	}
}

// superbox builds an assertion superbox with the given content boxes.
func superbox(label string, content ...*jumbf.Box) *jumbf.Box {
	return &jumbf.Box{Type: jumbf.TypeSuperbox, Children: append([]*jumbf.Box{{
		Type:        jumbf.TypeDescription,
		Description: &jumbf.Description{Toggles: jumbf.ToggleLabel, Label: label},
	}}, content...)}
}

func TestDecodeManifestErrors(t *testing.T) {
	claimBox := superbox(LabelClaimV2, &jumbf.Box{Type: "cbor", Payload: enc(t, validClaim())})
	sig := superbox(LabelSignature, &jumbf.Box{Type: "cbor"})
	as := superbox(LabelAssertions)
	tests := []struct {
		name string
		box  *jumbf.Box
		want error
	}{
		{"v1 claim", superbox("urn:c2pa:1", superbox(LabelClaimV1), sig, as), ErrUnsupportedClaim},
		{"no claim", superbox("urn:c2pa:1", sig, as), ErrMalformedManifest},
		{"no signature", superbox("urn:c2pa:1", claimBox, as), ErrMalformedManifest},
		{"no assertion store", superbox("urn:c2pa:1", claimBox, sig), ErrMalformedManifest},
		{"claim as json", superbox("urn:c2pa:1", superbox(LabelClaimV2, &jumbf.Box{Type: "json"}), sig, as), ErrMalformedManifest},
	}
	for _, tt := range tests {
		if _, err := DecodeManifest(tt.box); !errors.Is(err, tt.want) {
			t.Errorf("%s: error %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, err := DecodeManifest(superbox("urn:c2pa:1", claimBox, sig, as)); err != nil {
		t.Errorf("valid manifest: %v", err)
	}
	if _, err := DecodeStore(superbox("other")); !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("wrong store label: %v", err)
	}
	if _, err := DecodeStore(superbox(LabelStore)); !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("empty store: %v", err)
	}
}
