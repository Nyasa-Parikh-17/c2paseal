package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	gocose "github.com/veraison/go-cose"
)

// TestAlgorithms: every C2PA signature algorithm verifies with a matching
// key (signed independently by go-cose), and fails with the wrong key type,
// the wrong curve or a changed claim.
func TestAlgorithms(t *testing.T) {
	root, rootKey := ca(t)
	trust := &Options{TrustAnchors: []*x509.Certificate{root}, Now: func() time.Time { return t0.AddDate(0, 6, 0) }}
	ok := []string{SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}
	bad := []string{SigningCredentialTrusted, ClaimSignatureMismatch}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[gocose.Algorithm]crypto.Signer{
		gocose.AlgorithmES256: newKey(t),
		gocose.AlgorithmES384: p384,
		gocose.AlgorithmES512: p521,
		gocose.AlgorithmPS256: rsaKey,
		gocose.AlgorithmPS384: rsaKey,
		gocose.AlgorithmPS512: rsaKey,
		gocose.AlgorithmEdDSA: edKey,
	}
	for alg, key := range keys {
		leaf := create(t, leafTemplate(), root, key.Public(), rootKey)
		if got := codes(Signature(signedManifest(t, leaf, key, alg, claimBytes), nil, trust)); !slices.Equal(got, ok) {
			t.Errorf("%s: %q, want %q", alg, got, ok)
		}
		m := signedManifest(t, leaf, key, alg, claimBytes)
		m.Claim.Raw = []byte{0xA1, 0x61, 'a', 0x02}
		if got := codes(Signature(m, nil, trust)); !slices.Equal(got, bad) {
			t.Errorf("%s with a changed claim: %q, want %q", alg, got, bad)
		}
	}

	// ES384 header over a P-256 key, PS256 header over an EC key.
	p256 := newKey(t)
	ecLeaf := create(t, leafTemplate(), root, &p256.PublicKey, rootKey)
	m := signedManifest(t, ecLeaf, p256, gocose.AlgorithmES256, claimBytes)
	for _, alg := range []int64{cose.AlgES384, cose.AlgPS256, cose.AlgEd25519} {
		m.Signature.Alg = alg
		if got := codes(Signature(m, nil, trust)); !slices.Equal(got, bad) {
			t.Errorf("alg %d over a P-256 key: %q, want %q", alg, got, bad)
		}
	}
}

// TestPSSKey: certificates with an id-RSASSA-PSS key, which Go's x509 does
// not parse, still verify.
func TestPSSKey(t *testing.T) {
	root, rootKey := ca(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := create(t, leafTemplate(), root, &rsaKey.PublicKey, rootKey)
	// Rewrite the SPKI algorithm to id-RSASSA-PSS and re-sign the leaf.
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(leaf.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	spki.Algorithm = pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS}
	pssSPKI, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatal(err)
	}
	pssLeaf := &x509.Certificate{Raw: leaf.Raw, RawSubjectPublicKeyInfo: pssSPKI}
	pub, pss := publicKey(pssLeaf)
	if k, ok := pub.(*rsa.PublicKey); !ok || !pss || k.N.Cmp(rsaKey.N) != 0 {
		t.Fatalf("publicKey = %T, %v", pub, pss)
	}
	tbs := []byte("data")
	sig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest(crypto.SHA256, tbs), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCOSE(cose.AlgPS256, pub, tbs, sig); err != nil {
		t.Errorf("PS256 with a PSS key: %v", err)
	}
	if err := verifyCMS(pssLeaf, crypto.SHA256, tbs, sig); err != nil {
		t.Errorf("CMS with a PSS key: %v", err)
	}
	// Garbage SPKI: no key.
	if pub, _ := publicKey(&x509.Certificate{RawSubjectPublicKeyInfo: []byte{0x30, 0x00}}); pub != nil {
		t.Errorf("garbage SPKI gave %T", pub)
	}
}
