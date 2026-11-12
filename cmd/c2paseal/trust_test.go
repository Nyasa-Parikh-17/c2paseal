package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// TestTrustFlags: --trust can be repeated, --allowed-list trusts a signer
// without anchors, and --trust-config is read.
func TestTrustFlags(t *testing.T) {
	dir, _ := fixtures.Dir()
	file := fixture(t, "signed/small.jpg")
	root := filepath.Join(dir, "pki", "trust-anchors.pem")
	leafPEM := filepath.Join(dir, "pki", "leaf.pem")
	cfg := filepath.Join(t.TempDir(), "eku.cfg")
	if err := os.WriteFile(cfg, []byte("// extra\n1.3.6.1.4.1.99999.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := func(args ...string) string {
		t.Helper()
		_, out, _ := runCLI(append([]string{"verify", "--json"}, args...)...)
		var r struct {
			State string `json:"validation_state"`
		}
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return r.State
	}
	if s := state("--trust", root, "--trust", leafPEM, file); s != "Trusted" {
		t.Errorf("two --trust lists: %s", s)
	}
	if s := state("--allowed-list", leafPEM, file); s != "Trusted" {
		t.Errorf("--allowed-list: %s", s)
	}
	if s := state("--trust-config", cfg, file); s != "Valid" {
		t.Errorf("--trust-config: %s", s)
	}
	for _, args := range [][]string{
		{"verify", "--allowed-list", "missing.pem", file},
		{"verify", "--trust-config", "missing.cfg", file},
		{"verify", "--allowed-list", cfg, file}, // no certificates or hashes
	} {
		if code, _, _ := runCLI(args...); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

func TestLoaders(t *testing.T) {
	dir, _ := fixtures.Dir()
	leaf, err := os.ReadFile(filepath.Join(dir, "pki", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := c2paseal.LoadSigner(filepath.Join(dir, "pki", "leaf-chain.pem"), filepath.Join(dir, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(chain[0].Raw)
	p := filepath.Join(t.TempDir(), "allowed.txt")
	// A hash line, a PEM block (whose 64-character lines are not hashes),
	// and noise.
	body := base64.StdEncoding.EncodeToString(sum[:]) + "\nnot a hash\n" + string(leaf)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := c2paseal.LoadAllowedList(p)
	if err != nil || len(list) != 2 || list[0] != sum || list[1] != sum {
		t.Errorf("allowed list: %v %x", err, list)
	}
	cfg := filepath.Join(t.TempDir(), "eku.cfg")
	if err := os.WriteFile(cfg, []byte("// comment\n1.3.6.1.5.5.7.3.36\n\n1\n3.1.2\n1.02.3\n2.5.29.37\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ekus, err := c2paseal.LoadTrustConfig(cfg)
	if err != nil || len(ekus) != 2 || ekus[0].String() != "1.3.6.1.5.5.7.3.36" || ekus[1].String() != "2.5.29.37" {
		t.Errorf("trust config: %v %v", err, ekus)
	}
}

// TestSignOCSPResponse: sign --ocsp-response staples the given response.
func TestSignOCSPResponse(t *testing.T) {
	dir, _ := fixtures.Dir()
	st, err := c2paseal.Read(filepath.Join(dir, "ocsp", "good.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	resp := filepath.Join(t.TempDir(), "good.der")
	if err := os.WriteFile(resp, st.Active.Signature.OCSP[0], 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.jpg")
	code, b, errb := runCLI("sign", "--json", "--cert", filepath.Join(dir, "pki", "ocsp", "good-chain.pem"), "--key", filepath.Join(dir, "pki", "ocsp", "good.key"),
		"--in", fixture(t, "unsigned/small.jpg"), "--out", out, "--ocsp-response", resp)
	if code != exitValid {
		t.Fatalf("exit %d: %s %s", code, b, errb)
	}
	var r map[string]any
	if err := json.Unmarshal(b, &r); err != nil || r["ocsp_stapled"] != true {
		t.Errorf("result %s (%v)", b, err)
	}
	// A response for another signer is refused.
	code, _, _ = runCLI("sign", "--cert", filepath.Join(dir, "pki", "leaf-chain.pem"), "--key", filepath.Join(dir, "pki", "leaf.key"),
		"--in", fixture(t, "unsigned/small.jpg"), "--out", out, "--ocsp-response", resp)
	if code != exitInvalid {
		t.Errorf("wrong signer's response: exit %d", code)
	}
}
