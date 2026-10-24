package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	gocose "github.com/veraison/go-cose"
)

var (
	t0      = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	serial  = big.NewInt(1)
	testCA  *x509.Certificate
	testKey *ecdsa.PrivateKey
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func create(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	serial.Add(serial, big.NewInt(1))
	tmpl.SerialNumber = new(big.Int).Set(serial)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ca returns a test root valid for 2025–2030.
func ca(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	if testCA == nil {
		testKey = newKey(t)
		testCA = create(t, &x509.Certificate{
			Subject:               pkix.Name{CommonName: "Test Root", Organization: []string{"Test"}},
			NotBefore:             t0.AddDate(-1, 0, 0),
			NotAfter:              t0.AddDate(4, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}, &x509.Certificate{
			Subject: pkix.Name{CommonName: "Test Root", Organization: []string{"Test"}},
		}, &testKey.PublicKey, testKey)
		// Re-sign so the root is genuinely self-signed.
		testCA = create(t, testCA, testCA, &testKey.PublicKey, testKey)
	}
	return testCA, testKey
}

// leafTemplate is a valid C2PA signer valid for 2026.
func leafTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject:            pkix.Name{CommonName: "Signer", Organization: []string{"Test"}},
		NotBefore:          t0,
		NotAfter:           t0.AddDate(1, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUDocumentSigning},
	}
}

// signedManifest signs claim bytes with go-cose, independently of our
// verifier, and wraps the result in a Manifest.
func signedManifest(t *testing.T, leaf *x509.Certificate, key crypto.Signer, alg gocose.Algorithm, claim []byte) *manifest.Manifest {
	t.Helper()
	signer, err := gocose.NewSigner(alg, key)
	if err != nil {
		t.Fatal(err)
	}
	msg := gocose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(alg)
	msg.Headers.Protected[gocose.HeaderLabelX5Chain] = [][]byte{leaf.Raw}
	msg.Payload = claim
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	msg.Payload = nil // detached
	b, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	s, err := cose.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	const label = "urn:c2pa:3fa85f64-5717-4562-b3fc-2c963f66afa6"
	return &manifest.Manifest{
		Label:     label,
		Claim:     &manifest.Claim{Signature: "self#jumbf=/c2pa/" + label + "/c2pa.signature", Raw: claim},
		Signature: s,
	}
}

func codes(statuses []Status) []string {
	var out []string
	for _, s := range statuses {
		out = append(out, s.Code)
	}
	return out
}

var claimBytes = []byte{0xA1, 0x61, 'a', 0x01}

func TestSignatureCases(t *testing.T) {
	root, rootKey := ca(t)
	key := newKey(t)
	good := create(t, leafTemplate(), root, &key.PublicKey, rootKey)
	trust := &Options{TrustAnchors: []*x509.Certificate{root}, Now: func() time.Time { return t0.AddDate(0, 6, 0) }}
	noTrust := &Options{Now: trust.Now}
	afterExpiry := &Options{TrustAnchors: trust.TrustAnchors, Now: func() time.Time { return t0.AddDate(2, 0, 0) }}
	inValidity := t0.AddDate(0, 1, 0)
	pastExpiry := t0.AddDate(2, 0, 0)

	ok := []string{SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}
	tests := []struct {
		name string
		m    *manifest.Manifest
		time *time.Time
		opts *Options
		want []string
	}{
		{"valid, trusted", signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes), nil, trust, ok},
		{"valid, no anchors", signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes), nil, noTrust,
			[]string{SigningCredentialUntrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"expired now, no time-stamp", signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes), nil, afterExpiry,
			[]string{SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"expired now, time-stamp inside validity", signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes), &inValidity, afterExpiry, ok},
		{"time-stamp after expiry", signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes), &pastExpiry, trust,
			[]string{SigningCredentialExpired, SigningCredentialUntrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"ES384 unsupported", signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes), nil, trust, nil}, // alg patched below
	}
	tests[5].m.Signature.Alg = -35
	tests[5].want = []string{AlgorithmUnsupported, ClaimSignatureMismatch}

	tampered := signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes)
	tampered.Claim.Raw = []byte{0xA1, 0x61, 'a', 0x02}
	tests = append(tests, struct {
		name string
		m    *manifest.Manifest
		time *time.Time
		opts *Options
		want []string
	}{"claim changed", tampered, nil, trust, []string{SigningCredentialTrusted, ClaimSignatureMismatch}})

	for _, tt := range tests {
		if got := codes(Signature(tt.m, tt.time, tt.opts)); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSignatureStructure(t *testing.T) {
	root, rootKey := ca(t)
	key := newKey(t)
	good := create(t, leafTemplate(), root, &key.PublicKey, rootKey)
	opts := &Options{TrustAnchors: []*x509.Certificate{root}, Now: func() time.Time { return t0.AddDate(0, 6, 0) }}

	// Signature reference to another manifest.
	m := signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes)
	m.Claim.Signature = "self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature"
	if got := codes(Signature(m, nil, opts)); got[0] != ClaimSignatureMissing {
		t.Errorf("foreign signature ref: %q", got)
	}
	// Relative reference is fine.
	m.Claim.Signature = "self#jumbf=c2pa.signature"
	if got := codes(Signature(m, nil, opts)); slices.Contains(got, ClaimSignatureMissing) {
		t.Errorf("relative signature ref: %q", got)
	}
	// Bad manifest label.
	m.Label = "not-a-urn"
	m.Claim.Signature = "self#jumbf=c2pa.signature"
	if got := codes(Signature(m, nil, opts)); got[0] != ClaimMalformed {
		t.Errorf("bad label: %q", got)
	}
	// Undecodable signature.
	m = signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes)
	m.Signature = nil
	if got := codes(Signature(m, nil, opts)); !slices.Equal(got, []string{ClaimSignatureMismatch}) {
		t.Errorf("no signature: %q", got)
	}
	// DER-encoded EC signature.
	m = signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes)
	r, s := new(big.Int).SetBytes(m.Signature.Signature[:32]), new(big.Int).SetBytes(m.Signature.Signature[32:])
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	m.Signature.Signature = der
	if got := codes(Signature(m, nil, opts)); !slices.Equal(got, []string{SigningCredentialInvalid, ClaimSignatureMismatch}) {
		t.Errorf("DER signature: %q", got)
	}
	// Wrong trust anchor.
	otherKey := newKey(t)
	other := create(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Other"}, NotBefore: t0.AddDate(-1, 0, 0),
		NotAfter: t0.AddDate(4, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign},
		&x509.Certificate{Subject: pkix.Name{CommonName: "Other"}}, &otherKey.PublicKey, otherKey)
	m = signedManifest(t, good, key, gocose.AlgorithmES256, claimBytes)
	if got := codes(Signature(m, nil, &Options{TrustAnchors: []*x509.Certificate{other}, Now: opts.Now})); got[0] != SigningCredentialUntrusted {
		t.Errorf("wrong anchor: %q", got)
	}
}

// TestProfile covers each certificate-profile rule from c2pa-rs.
func TestProfile(t *testing.T) {
	root, rootKey := ca(t)
	at := t0.AddDate(0, 6, 0)
	key := newKey(t)

	mod := func(f func(*x509.Certificate)) *x509.Certificate {
		tmpl := leafTemplate()
		f(tmpl)
		return create(t, tmpl, root, &key.PublicKey, rootKey)
	}
	noAKIParent := *root
	noAKIParent.SubjectKeyId = nil
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		cert *x509.Certificate
		want string // expected explanation, "" for a pass
	}{
		{"valid", mod(func(*x509.Certificate) {}), ""},
		{"C2PA signing EKU only", mod(func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidEKUC2PASigning}
		}), ""},
		{"expired", mod(func(c *x509.Certificate) { c.NotAfter = t0.AddDate(0, 1, 0) }), "certificate expired"},
		{"not yet valid", mod(func(c *x509.Certificate) { c.NotBefore = at.AddDate(0, 0, 1) }), "certificate expired"},
		{"any EKU", mod(func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageAny) }), "certificate 'any' EKU not allowed"},
		{"server auth only", mod(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.UnknownExtKeyUsage = nil
		}), "certificate missing required EKU"},
		{"time-stamping plus email", mod(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageEmailProtection}
		}), "certificate invalid set of EKUs"},
		{"no EKU", mod(func(c *x509.Certificate) { c.ExtKeyUsage, c.UnknownExtKeyUsage = nil, nil }), "certificate params incorrect"},
		{"keyCertSign on end entity", mod(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }), "certificate missing digitalSignature EKU"},
		{"no key usage bits", mod(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }), "certificate params incorrect"},
		{"no AKI", create(t, leafTemplate(), &noAKIParent, &key.PublicKey, rootKey), "certificate params incorrect"},
		{"unknown critical extension", mod(func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}}}
		}), "certificate params incorrect"},
		{"CA as signer", mod(func(c *x509.Certificate) {
			c.IsCA, c.BasicConstraintsValid = true, true
			c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		}), "expected end-entity certificate"},
		{"self-signed CA", root, "certificate issuer and subject cannot be the same (self-signed disallowed)"},
		{"RSA 1024", create(t, leafTemplate(), root, &rsaKey.PublicKey, rootKey), "certificate key length too short"},
		{"P-224", create(t, leafTemplate(), root, &p224.PublicKey, rootKey), "certificate unsupported EC curve"},
	}
	for _, tt := range tests {
		_, got := checkProfile(tt.cert, at, signerEKUs)
		if got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestKindOf(t *testing.T) {
	for code, want := range map[string]Kind{
		ClaimSignatureValidated: Success, SigningCredentialTrusted: Success,
		TimeStampUntrusted: Informational, SigningCredentialUntrusted: Failure,
		ClaimSignatureMismatch: Failure, "made.up": Failure,
	} {
		if got := KindOf(code); got != want {
			t.Errorf("KindOf(%s) = %v, want %v", code, got, want)
		}
	}
}

// TestSigStructure pins the Sig_structure encoding: a 4-array of
// "Signature1", protected bstr, empty external_aad, claim bstr.
func TestSigStructure(t *testing.T) {
	b, err := cbormode.Enc.Marshal([]any{"Signature1", []byte{0xA0}, []byte{}, []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x84, 0x6A, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1', 0x41, 0xA0, 0x40, 0x41, 0x01}
	if string(b) != string(want) {
		t.Errorf("Sig_structure % x, want % x", b, want)
	}
}
