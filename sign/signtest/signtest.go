// Package signtest helps test key providers (see sign.KeyProvider). It
// issues certificates under C2paSeal's TEST ONLY PKI, whose private keys are
// public, and checks that files signed through a crypto.Signer validate in
// this library and in c2patool. Nothing it produces proves anything about
// who signed a file.
package signtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// TestdataDir returns the repository's testdata directory.
func TestdataDir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("signtest: cannot locate testdata")
	}
	dir := filepath.Join(filepath.Dir(file), "..", "..", "testdata")
	if _, err := os.Stat(filepath.Join(dir, "pki", "intermediate.pem")); err != nil {
		t.Fatalf("signtest: testdata: %v", err)
	}
	return dir
}

// Chain issues a signing certificate for pub under the TEST ONLY
// intermediate CA, with the profile of testdata/pki/leaf.pem (digital
// signature; emailProtection and documentSigning EKUs), valid from an hour
// ago for a day. It returns the certificate and the intermediate, the chain
// for sign.Options.
func Chain(t testing.TB, pub crypto.PublicKey) []*x509.Certificate {
	t.Helper()
	dir := filepath.Join(TestdataDir(t), "pki")
	inter, err := c2paseal.LoadChain(filepath.Join(dir, "intermediate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := sign.OpenKey(t.Context(), filepath.Join(dir, "intermediate.key"))
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("signtest: public key: %v", err)
	}
	var parsed struct {
		Algo pkix.AlgorithmIdentifier
		Key  asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &parsed); err != nil {
		t.Fatal(err)
	}
	ski := sha1.Sum(parsed.Key.Bytes)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "C2paSeal Test Signer (key provider)", Organization: []string{"C2paSeal TEST ONLY"}, OrganizationalUnit: []string{"Not for production"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}}, // documentSigning
		BasicConstraintsValid: true,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        inter[0].SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter[0], pub, interKey)
	if err != nil {
		t.Fatalf("signtest: issue certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{leaf, inter[0]}
}

// Check signs a JPEG and a PNG from testdata/unsigned through signer, with
// chain (see Chain), and checks each signed file:
//
//   - this library: Valid with default trust, Trusted under the TEST ONLY
//     root;
//   - c2patool, if it is on PATH: the same two states. Set
//     C2PASEAL_REQUIRE_C2PATOOL=1 to fail instead of skipping that part
//     when it is missing (as CI does).
//
// It returns the signed files' paths, in t.TempDir().
func Check(t *testing.T, signer crypto.Signer, chain []*x509.Certificate) []string {
	t.Helper()
	td := TestdataDir(t)
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("signtest: signer's public key is %T, want *ecdsa.PublicKey", signer.Public())
	}
	var out []string
	for _, name := range []string{"small.jpg", "small.png"} {
		in := filepath.Join(td, "unsigned", name)
		dst := filepath.Join(t.TempDir(), "signed-"+name)
		if err := c2paseal.Sign(in, dst, &c2paseal.SignOptions{Chain: chain, Signer: signer, Title: name}); err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		out = append(out, dst)
		CheckFile(t, dst)
	}
	return out
}

// CheckFile checks a file signed with a chain from Chain (or the TEST ONLY
// leaf): Valid with default trust and Trusted under the TEST ONLY root, in
// this library and, if it is on PATH, in c2patool. As in Check,
// C2PASEAL_REQUIRE_C2PATOOL=1 makes a missing c2patool a failure.
func CheckFile(t *testing.T, path string) {
	t.Helper()
	name := filepath.Base(path)
	anchorsPath := filepath.Join(TestdataDir(t), "pki", "trust-anchors.pem")
	anchors, err := c2paseal.LoadTrustAnchors(anchorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if st := c2paseal.VerifyFile(path, nil).State(); st != verify.Valid {
		t.Errorf("%s: C2paSeal (default trust): %s, want Valid", name, st)
	}
	if st := c2paseal.VerifyFile(path, &c2paseal.VerifyOptions{TrustAnchors: anchors}).State(); st != verify.Trusted {
		t.Errorf("%s: C2paSeal (TEST ONLY root): %s, want Trusted", name, st)
	}
	c2patool, err := exec.LookPath("c2patool")
	if err != nil {
		if os.Getenv("C2PASEAL_REQUIRE_C2PATOOL") == "1" {
			t.Fatalf("signtest: C2PASEAL_REQUIRE_C2PATOOL=1 but c2patool is not on PATH: %v", err)
		}
		t.Logf("%s: c2patool not on PATH, skipped", name)
		return
	}
	def, err := c2patoolState(c2patool, path)
	if err != nil || def != verify.Valid {
		t.Errorf("%s: c2patool (default trust): %s, %v; want Valid", name, def, err)
	}
	tr, err := c2patoolState(c2patool, path, "trust", "--trust_anchors", relSlash(anchorsPath))
	if err != nil || tr != verify.Trusted {
		t.Errorf("%s: c2patool (TEST ONLY root): %s, %v; want Trusted", name, tr, err)
	}
	t.Logf("%s: c2patool says %s (default trust), %s (TEST ONLY root)", name, def, tr)
}

// c2patoolState runs `c2patool <file> --detailed [extra]` and returns its
// validation_state.
func c2patoolState(c2patool, file string, extra ...string) (verify.State, error) {
	cmd := exec.Command(c2patool, append([]string{file, "--detailed"}, extra...)...)
	b, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", errors.New(string(ee.Stderr))
		}
		return "", err
	}
	var r struct {
		State verify.State `json:"validation_state"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", err
	}
	return r.State, nil
}

// relSlash returns p relative to the working directory with forward
// slashes: c2patool reads "C:/..." as a URL with scheme "c".
func relSlash(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(p)
	}
	r, err := filepath.Rel(wd, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}
