package c2paseal

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// TestParseMatchesLoad checks that the byte-level Parse* functions give
// what the Load* functions give for the same files, and that the Load*
// errors still name the file.
func TestParseMatchesLoad(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	certPath, keyPath := filepath.Join(dir, "pki", "leaf-chain.pem"), filepath.Join(dir, "pki", "leaf.key")
	lc, lk, err := LoadSigner(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pc, pk, err := ParseSigner(read("pki/leaf-chain.pem"), read("pki/leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pc) != len(lc) || !pc[0].Equal(lc[0]) || !pk.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(lk.Public()) {
		t.Error("ParseSigner differs from LoadSigner")
	}

	la, err := LoadTrustAnchors(filepath.Join(dir, "pki", "trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pa, err := ParseTrustAnchors(read("pki/trust-anchors.pem"))
	if err != nil || len(pa) != len(la) || !pa[0].Equal(la[0]) {
		t.Errorf("ParseTrustAnchors differs from LoadTrustAnchors (%v)", err)
	}
	if l, err := ParseAllowedList(read("pki/leaf.pem")); err != nil || len(l) != 1 {
		t.Errorf("ParseAllowedList(leaf.pem) = %d hashes, %v", len(l), err)
	}
	if got := ParseTrustConfig([]byte("# comment\n1.3.6.1.5.5.7.3.4\n")); len(got) != 1 || got[0].String() != "1.3.6.1.5.5.7.3.4" {
		t.Errorf("ParseTrustConfig = %v", got)
	}

	// Errors: Load* names the file, Parse* says which input.
	if _, _, err := LoadSigner(keyPath, keyPath); err == nil || !strings.Contains(err.Error(), keyPath) {
		t.Errorf("LoadSigner with a key as certificate: %v, want the path", err)
	}
	if _, _, err := ParseSigner(read("pki/leaf.key"), nil); err == nil || !strings.Contains(err.Error(), "certificate input") {
		t.Errorf("ParseSigner without certificates: %v", err)
	}
	if _, _, err := ParseSigner(read("pki/leaf-chain.pem"), []byte("x")); err == nil || !strings.Contains(err.Error(), "key input") {
		t.Errorf("ParseSigner without a key: %v", err)
	}
	if _, err := ParseTrustAnchors(nil); err == nil {
		t.Error("ParseTrustAnchors(nil) succeeded")
	}
	if _, err := ParseAllowedList([]byte("nothing")); err == nil {
		t.Error("ParseAllowedList(nothing) succeeded")
	}
}
