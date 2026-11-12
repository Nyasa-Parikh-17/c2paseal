package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// relPath makes p relative to the working directory: c2patool reads an
// absolute Windows path ("C:/...") as a URL.
func relPath(t *testing.T, p string) string {
	t.Helper()
	wd, _ := os.Getwd()
	r, err := filepath.Rel(wd, p)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(r)
}

// customEKUSigner issues a claim signer from the test intermediate whose
// only EKU is 1.3.6.1.4.1.99999.1, which the C2PA defaults do not accept.
func customEKUSigner(t *testing.T) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	dir, _ := fixtures.Dir()
	interChain, interKeyAny := loadPair(t, filepath.Join(dir, "pki", "intermediate.pem"), filepath.Join(dir, "pki", "intermediate.key"))
	inter, interKey := interChain[0], interKeyAny.(*ecdsa.PrivateKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ski := sha256.Sum256(pub)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "C2paSeal Custom EKU Signer", Organization: []string{"C2paSeal TEST ONLY"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski[:20],
		AuthorityKeyId:        inter.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &key.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return []*x509.Certificate{leaf, inter}, key
}

// issue creates a certificate signed by parent.
func issueCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// deepChain issues intermediate 2 under parent and a claim signer under it.
func deepChain(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (inter2, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p2, _ := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	ski2 := sha256.Sum256(p2)
	inter2 = issueCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "C2paSeal Test Intermediate 2", Organization: []string{"C2paSeal TEST ONLY"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: ski2[:20], AuthorityKeyId: parent.SubjectKeyId,
	}, parent, &k2.PublicKey, parentKey)
	kl, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pl, _ := x509.MarshalPKIXPublicKey(&kl.PublicKey)
	skil := sha256.Sum256(pl)
	leaf = issueCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: "C2paSeal Deep Chain Signer", Organization: []string{"C2paSeal TEST ONLY"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		SubjectKeyId: skil[:20], AuthorityKeyId: inter2.SubjectKeyId,
	}, inter2, &kl.PublicKey, k2)
	return inter2, leaf, kl
}

// TestC2patoolChains: a signer under two intermediates verifies the same
// as in c2patool, with x5chain in issuing order, out of order, missing the
// middle certificate, and under the test intermediate whose pathlen is 0.
func TestC2patoolChains(t *testing.T) {
	needC2patool(t)
	dir, _ := fixtures.Dir()
	rootChain, rootKeyAny := loadPair(t, filepath.Join(dir, "pki", "root.pem"), filepath.Join(dir, "pki", "root.key"))
	rootCert, rootKey := rootChain[0], rootKeyAny.(*ecdsa.PrivateKey)
	now := time.Now()
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p1, _ := x509.MarshalPKIXPublicKey(&k1.PublicKey)
	ski1 := sha256.Sum256(p1)
	inter1 := issueCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 7), Subject: pkix.Name{CommonName: "C2paSeal Test Intermediate 1", Organization: []string{"C2paSeal TEST ONLY"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: ski1[:20], AuthorityKeyId: rootCert.SubjectKeyId,
	}, rootCert, &k1.PublicKey, rootKey)
	inter2, leaf, kl := deepChain(t, inter1, k1)

	pinChain, pinKeyAny := loadPair(t, filepath.Join(dir, "pki", "intermediate.pem"), filepath.Join(dir, "pki", "intermediate.key"))
	pinInter2, pinLeaf, pinKey := deepChain(t, pinChain[0], pinKeyAny.(*ecdsa.PrivateKey))

	root := anchors(t)
	tmp := t.TempDir()
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		key   *ecdsa.PrivateKey
	}{
		{"in order", []*x509.Certificate{leaf, inter2, inter1}, kl},
		{"out of order", []*x509.Certificate{leaf, inter1, inter2}, kl},
		{"middle missing", []*x509.Certificate{leaf, inter1}, kl},
		{"pathlen 0 exceeded", []*x509.Certificate{pinLeaf, pinInter2, pinChain[0]}, pinKey},
	} {
		name := tc.name
		out, err := JPEG(unsignedFile(t, "small.jpg"), &Options{Chain: tc.chain, Signer: tc.key})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(tmp, "chain.jpg")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		b, err := exec.Command("c2patool", relPath(t, path), "trust", "--trust_anchors", "../testdata/pki/trust-anchors.pem").Output()
		if err != nil {
			t.Fatalf("%s: c2patool: %v", name, err)
		}
		wantState, want := renderReport(t, b)
		gotState, got := renderOurs(verify.File(out, &verify.Options{TrustAnchors: root}))
		if gotState != wantState || !slices.Equal(got, want) {
			t.Errorf("%s:\n got  %s %q\n want %s %q", name, gotState, got, wantState, want)
		}
		t.Logf("%s: %s", name, gotState)
	}
}

// TestC2patoolTrustOptions: the allowed list (PEM and hash forms) and the
// trust configuration give the same results as c2patool's --allowed_list
// and --trust_config.
func TestC2patoolTrustOptions(t *testing.T) {
	needC2patool(t)
	dir, _ := fixtures.Dir()
	tmp := t.TempDir()
	chain, _ := testPKI(t)
	leafPEM := filepath.Join(dir, "pki", "leaf.pem")
	hashFile := filepath.Join(tmp, "allowed.txt")
	sum := sha256.Sum256(chain[0].Raw)
	if err := os.WriteFile(hashFile, []byte("# allowed\n"+base64.StdEncoding.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(tmp, "eku.cfg")
	if err := os.WriteFile(cfg, []byte("// custom\n1.3.6.1.4.1.99999.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	signed, err := os.ReadFile(filepath.Join(dir, "signed", "ts.png"))
	if err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(dir, "signed", "ts.png")

	cchain, ckey := customEKUSigner(t)
	custom, err := JPEG(unsignedFile(t, "small.jpg"), &Options{Chain: cchain, Signer: ckey})
	if err != nil {
		t.Fatal(err)
	}
	customPath := filepath.Join(tmp, "custom.jpg")
	if err := os.WriteFile(customPath, custom, 0o644); err != nil {
		t.Fatal(err)
	}
	root := anchors(t)
	ekus := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}

	for _, tc := range []struct {
		name string
		file []byte
		path string
		args []string
		opts *verify.Options
	}{
		{"allowed list PEM", signed, signedPath, []string{"--allowed_list", relPath(t, leafPEM)}, &verify.Options{AllowedList: [][32]byte{sum}}},
		{"allowed list hash", signed, signedPath, []string{"--allowed_list", relPath(t, hashFile)}, &verify.Options{AllowedList: [][32]byte{sum}}},
		{"custom EKU without config", custom, customPath, []string{"--trust_anchors", "../testdata/pki/trust-anchors.pem"}, &verify.Options{TrustAnchors: root}},
		{"custom EKU with config", custom, customPath, []string{"--trust_anchors", "../testdata/pki/trust-anchors.pem", "--trust_config", relPath(t, cfg)},
			&verify.Options{TrustAnchors: root, ExtraEKUs: ekus}},
	} {
		args := append([]string{relPath(t, tc.path), "trust"}, tc.args...)
		b, err := exec.Command("c2patool", args...).Output()
		if err != nil {
			t.Fatalf("%s: c2patool: %v", tc.name, err)
		}
		wantState, want := renderReport(t, b)
		gotState, got := renderOurs(verify.File(tc.file, tc.opts))
		if gotState != wantState || !slices.Equal(got, want) {
			t.Errorf("%s:\n got  %s %q\n want %s %q", tc.name, gotState, got, wantState, want)
		}
		t.Logf("%s: %s", tc.name, gotState)
	}
}
