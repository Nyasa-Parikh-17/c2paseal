package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/examples/internal/fixtures"
)

func TestRun(t *testing.T) {
	td := fixtures.Testdata(t)
	dir := t.TempDir()
	in := fixtures.Copy(t, td, "unsigned/small.png", dir)
	var out bytes.Buffer
	err := run([]string{
		"--cert", filepath.Join(td, "pki", "leaf-chain.pem"),
		"--key", filepath.Join(td, "pki", "leaf.key"),
		"--trust", filepath.Join(td, "pki", "trust-anchors.pem"),
		in,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "small.signed.png") || !strings.Contains(out.String(), "state: Trusted") {
		t.Errorf("output:\n%s", out.String())
	}
	if err := run([]string{in}, &out); err == nil {
		t.Error("no error without --cert and --key")
	}
}
