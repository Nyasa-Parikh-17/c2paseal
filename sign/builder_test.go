package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// testPKI loads the TEST ONLY signer chain and key from testdata/pki.
func testPKI(t *testing.T) ([]*x509.Certificate, crypto.Signer) {
	t.Helper()
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := os.ReadFile(filepath.Join(dir, "pki", "leaf-chain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for blk, rest := pem.Decode(pemBytes); blk != nil; blk, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return chain, key.(crypto.Signer)
}

// seeded returns a deterministic randomness source for salts and UUIDs.
func seeded(seed uint64) *mrand.ChaCha8 {
	var s [32]byte
	s[0] = byte(seed)
	return mrand.NewChaCha8(s)
}

// readBack parses serialised store bytes with the read path.
func readBack(t *testing.T, b []byte) (*jumbf.Box, *manifest.Manifest) {
	t.Helper()
	root, err := jumbf.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jumbf.Serialize(root), b) {
		t.Fatal("store does not round-trip through the JUMBF parser")
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("%d manifests, want 1", len(ms))
	}
	return root, ms[0]
}

func TestBuildRoundTrip(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	thumb, err := os.ReadFile(filepath.Join(dir, "unsigned", "small.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	agent := map[string]any{"name": "test editor", "version": "2"}

	tests := []struct {
		name string
		opts *Options
	}{
		{"defaults", &Options{Chain: chain, Signer: key}},
		{"title and generator", &Options{Chain: chain, Signer: key, Title: "A title", Generator: "my-app", GeneratorVersion: "9.9"}},
		{"thumbnail", &Options{Chain: chain, Signer: key, Thumbnail: &assertion.Thumbnail{Format: "image/jpeg", Data: thumb}}},
		{"actions", &Options{Chain: chain, Signer: key, Actions: []assertion.Action{
			{Action: "c2pa.created", DigitalSourceType: "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"},
			{Action: "c2pa.edited", SoftwareAgent: agent, Description: "cropped"},
		}}},
		{"leaf only chain", &Options{Chain: chain[:1], Signer: key, DigitalSourceType: "http://cv.iptc.org/newscodes/digitalsourcetype/minorHumanEdits"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Rand = seeded(1)
			b, err := Build(tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			_, m := readBack(t, b.Bytes())

			// Claim.
			name, version := tt.opts.generator()
			c := m.Claim
			if m.Label != b.Label || c.InstanceID != b.Claim.InstanceID || c.Title != tt.opts.Title ||
				c.ClaimGeneratorInfo.Name() != name || c.ClaimGeneratorInfo.Version() != version ||
				c.Signature != "self#jumbf=/c2pa/"+b.Label+"/c2pa.signature" || c.Alg != "sha256" {
				t.Errorf("claim read back as %+v", c)
			}
			for _, check := range m.HashChecks {
				if !check.Match || check.Err != nil {
					t.Errorf("hashed URI %s: match %v, err %v", check.Ref.URL, check.Match, check.Err)
				}
			}

			// Assertions.
			labels := []string{}
			for _, a := range m.Assertions {
				labels = append(labels, a.Label)
				if a.Err != nil {
					t.Errorf("%s: %v", a.Label, a.Err)
				}
			}
			want := []string{"c2pa.actions.v2", "c2pa.hash.data"}
			if tt.opts.Thumbnail != nil {
				want = append(want, "c2pa.thumbnail.claim")
			}
			if !slices.Equal(labels, want) {
				t.Errorf("assertions %q, want %q", labels, want)
			}
			acts := m.Assertion("c2pa.actions.v2").Value.(*assertion.Actions)
			if gotActs, wantActs := normalize(t, acts.Actions), normalize(t, tt.opts.actions()); !reflect.DeepEqual(gotActs, wantActs) {
				t.Errorf("actions %v, want %v", gotActs, wantActs)
			}
			dh := m.Assertion("c2pa.hash.data").Value.(*assertion.DataHash)
			if len(dh.Exclusions) != 1 || dh.Exclusions[0] != (assertion.Exclusion{}) || !bytes.Equal(dh.Hash, make([]byte, 32)) || dh.Name != "jumbf manifest" {
				t.Errorf("placeholder hash.data %+v", dh)
			}
			if tt.opts.Thumbnail != nil {
				th := m.Assertion("c2pa.thumbnail.claim").Value.(*assertion.Thumbnail)
				if th.Format != "image/jpeg" || !bytes.Equal(th.Data, thumb) {
					t.Errorf("thumbnail %q, %d bytes", th.Format, len(th.Data))
				}
			}

			// Signature placeholder.
			s := m.Signature
			if m.SignatureErr != nil || s.Alg != cose.AlgES256 || len(s.X5Chain) != len(tt.opts.Chain) ||
				!bytes.Equal(s.X5Chain[0], chain[0].Raw) || !bytes.Equal(s.Signature, make([]byte, 64)) {
				t.Errorf("signature %+v, err %v", s, m.SignatureErr)
			}
		})
	}
}

// normalize compares actions through their CBOR encoding.
func normalize(t *testing.T, v any) any {
	t.Helper()
	b, err := cbormode.Enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := cbormode.Dec.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSeal: after filling in the binding and sealing, the read-back claim
// signature verifies and every hashed URI still matches.
func TestSeal(t *testing.T) {
	chain, key := testPKI(t)
	b, err := Build(&Options{Chain: chain, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	before := len(b.Bytes())
	if _, err := b.SetExclusion(2, 4000); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetDigest(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if len(b.Bytes()) != before {
		t.Fatalf("store changed size: %d → %d", before, len(b.Bytes()))
	}
	_, m := readBack(t, b.Bytes())
	got := verify.Signature(m, nil, nil)
	if !slices.ContainsFunc(got, func(s verify.Status) bool { return s.Code == verify.ClaimSignatureValidated }) {
		t.Errorf("signature does not verify: %+v", got)
	}
	for _, c := range m.HashChecks {
		if !c.Match {
			t.Errorf("%s does not match after Seal", c.Ref.URL)
		}
	}
	dh := m.Assertion("c2pa.hash.data").Value.(*assertion.DataHash)
	if dh.Exclusions[0] != (assertion.Exclusion{Start: 2, Length: 4000}) || dh.Hash[0] != 7 {
		t.Errorf("hash.data after backfill: %+v", dh)
	}
}

func TestHashDataFixedWidth(t *testing.T) {
	small, l1 := encodeHashData(0, 0, nil)
	big, l2 := encodeHashData(math.MaxUint64, 1<<40, bytes.Repeat([]byte{1}, 32))
	if len(small) != len(big) || l1 != l2 {
		t.Fatalf("encoding size depends on values: %d vs %d", len(small), len(big))
	}
	var dh assertion.DataHash
	if err := cbormode.Dec.Unmarshal(big, &dh); err != nil {
		t.Fatal(err)
	}
	if dh.Exclusions[0].Start != math.MaxUint64 || dh.Exclusions[0].Length != 1<<40 || dh.Alg != "sha256" || dh.Pad == nil {
		t.Errorf("decoded %+v", dh)
	}
}

func TestBuildDeterministic(t *testing.T) {
	chain, key := testPKI(t)
	a, err1 := Build(&Options{Chain: chain, Signer: key, Rand: seeded(3)})
	b, err2 := Build(&Options{Chain: chain, Signer: key, Rand: seeded(3)})
	c, err3 := Build(&Options{Chain: chain, Signer: key})
	if err := errors.Join(err1, err2, err3); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("same Rand gave different stores")
	}
	if a.Label == c.Label {
		t.Error("crypto/rand gave the seeded label")
	}
}

func TestOptionsErrors(t *testing.T) {
	chain, key := testPKI(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Cert := *chain[0]
	p384Cert.PublicKey = &p384.PublicKey

	tests := []struct {
		name string
		opts Options
		want error
	}{
		{"no chain", Options{Signer: key}, ErrNoSigner},
		{"no key", Options{Chain: chain}, ErrNoSigner},
		{"wrong key", Options{Chain: chain, Signer: other}, ErrKeyMismatch},
		{"P-384", Options{Chain: []*x509.Certificate{&p384Cert}, Signer: p384}, ErrUnsupported},
		{"empty actions", Options{Chain: chain, Signer: key, Actions: []assertion.Action{}}, ErrBadActions},
		{"first not created", Options{Chain: chain, Signer: key, Actions: []assertion.Action{{Action: "c2pa.edited"}}}, ErrBadActions},
		{"opened", Options{Chain: chain, Signer: key, Actions: []assertion.Action{{Action: "c2pa.opened"}}}, ErrBadActions},
		{"created twice", Options{Chain: chain, Signer: key, Actions: []assertion.Action{
			{Action: "c2pa.created", DigitalSourceType: "x"}, {Action: "c2pa.created", DigitalSourceType: "x"}}}, ErrBadActions},
		{"no source type", Options{Chain: chain, Signer: key, Actions: []assertion.Action{{Action: "c2pa.created"}}}, ErrBadActions},
		{"placed", Options{Chain: chain, Signer: key, Actions: []assertion.Action{
			{Action: "c2pa.created", DigitalSourceType: "x"}, {Action: "c2pa.placed"}}}, ErrBadActions},
		{"unnamed action", Options{Chain: chain, Signer: key, Actions: []assertion.Action{
			{Action: "c2pa.created", DigitalSourceType: "x"}, {}}}, ErrBadActions},
		{"empty thumbnail", Options{Chain: chain, Signer: key, Thumbnail: &assertion.Thumbnail{Format: "image/jpeg"}}, ErrBadThumbnail},
	}
	for _, tt := range tests {
		if _, err := Build(&tt.opts); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
}
