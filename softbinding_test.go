package c2paseal_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
)

// TestSoftBinding: a soft binding given when signing is recorded as a
// c2pa.soft-binding assertion that reads back with its algorithm and value,
// and the file still validates in c2patool.
func TestSoftBinding(t *testing.T) {
	td := signtest.TestdataDir(t)
	chain, key, err := c2paseal.LoadSigner(filepath.Join(td, "pki", "leaf-chain.pem"), filepath.Join(td, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unsigned/large.jpg", "unsigned/sample.avif"} {
		in, err := os.ReadFile(filepath.Join(td, name))
		if err != nil {
			t.Fatal(err)
		}
		opts := &c2paseal.SignOptions{Chain: chain, Signer: key, SoftBindings: []sign.SoftBinding{
			{Alg: "io.github.nyasa-parikh-17.c2paseal.watermark.1", Value: "c2fa5ea1d0c0ffee"},
			{Alg: "com.example.fingerprint", Value: "abc"},
		}}
		signed, err := c2paseal.SignAsset(in, opts)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "sb-"+filepath.Base(name))
		os.WriteFile(out, signed.File, 0o644)
		signtest.CheckFile(t, out)
		s, err := c2paseal.ReadBytes(signed.File)
		if err != nil {
			t.Fatal(err)
		}
		for label, want := range map[string][2]string{
			assertion.LabelSoftBinding:         {"io.github.nyasa-parikh-17.c2paseal.watermark.1", "c2fa5ea1d0c0ffee"},
			assertion.LabelSoftBinding + "__1": {"com.example.fingerprint", "abc"},
		} {
			a := s.Active.Assertion(label)
			if a == nil {
				t.Fatalf("%s: no %s", name, label)
			}
			sb, ok := a.Value.(*assertion.SoftBinding)
			if !ok || sb.Alg != want[0] || len(sb.Blocks) != 1 || sb.Blocks[0].Value != want[1] {
				t.Errorf("%s: %s = %+v (%v)", name, label, a.Value, a.Err)
			}
		}
	}
	for _, bad := range [][]sign.SoftBinding{{{Alg: "x"}}, {{Value: "y"}}, {{Alg: "x", Value: "1"}, {Alg: "x", Value: "2"}}} {
		if _, err := c2paseal.SignAsset(nil, &c2paseal.SignOptions{Chain: chain, Signer: key, SoftBindings: bad}); !errors.Is(err, sign.ErrBadSoftBind) {
			in, _ := os.ReadFile(filepath.Join(td, "unsigned", "small.jpg"))
			if _, err := c2paseal.SignAsset(in, &c2paseal.SignOptions{Chain: chain, Signer: key, SoftBindings: bad}); !errors.Is(err, sign.ErrBadSoftBind) {
				t.Errorf("%+v: %v", bad, err)
			}
		}
	}
}
