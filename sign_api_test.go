package c2paseal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func TestSign(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	chain, key, err := LoadSigner(filepath.Join(dir, "pki", "leaf-chain.pem"), filepath.Join(dir, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain has %d certificates, want 2", len(chain))
	}
	opts := &SignOptions{Chain: chain, Signer: key}
	out := filepath.Join(t.TempDir(), "signed.jpg")
	if err := Sign(filepath.Join(dir, "unsigned", "exif.jpg"), out, opts); err != nil {
		t.Fatal(err)
	}
	if got := VerifyFile(out, nil).State(); got != verify.Valid {
		t.Errorf("signed file state %s, want Valid", got)
	}
	s, err := Read(out)
	if err != nil || s.Active.Claim.ClaimGeneratorInfo.Name() != "C2paSeal" {
		t.Errorf("Read signed file: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(out))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %d entries", len(entries))
	}

	if err := Sign(filepath.Join(dir, "unsigned", "small.png"), out, opts); !errors.Is(err, ErrSignFormat) {
		t.Errorf("signing PNG: %v, want ErrSignFormat", err)
	}
	if err := Sign(filepath.Join(dir, "no-such.jpg"), out, opts); err == nil {
		t.Error("signing a missing file succeeded")
	}
	if err := Sign(filepath.Join(dir, "unsigned", "small.jpg"), filepath.Join(dir, "no-such-dir", "x.jpg"), opts); err == nil {
		t.Error("writing into a missing directory succeeded")
	}
}

func TestLoadSignerErrors(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	junk := filepath.Join(tmp, "junk.pem")
	if err := os.WriteFile(junk, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "pki", "leaf-chain.pem")
	key := filepath.Join(dir, "pki", "leaf.key")
	for _, c := range []struct{ cert, key string }{
		{filepath.Join(tmp, "missing.pem"), key},
		{junk, key},
		{cert, filepath.Join(tmp, "missing.key")},
		{cert, junk},
		{cert, cert}, // a certificate where the key should be
	} {
		if _, _, err := LoadSigner(c.cert, c.key); err == nil {
			t.Errorf("LoadSigner(%s, %s) succeeded", filepath.Base(c.cert), filepath.Base(c.key))
		}
	}
}
