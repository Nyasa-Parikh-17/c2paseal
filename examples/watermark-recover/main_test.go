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
	var out bytes.Buffer
	err := run([]string{
		"--cert", filepath.Join(td, "pki", "leaf-chain.pem"),
		"--key", filepath.Join(td, "pki", "leaf.key"),
		"--dir", t.TempDir(),
		filepath.Join(td, "..", "watermark", "testdata", "earth_apollo17.jpg"),
	}, &out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "signature valid: true; copy's bytes changed since signing: true") {
		t.Errorf("output:\n%s", out.String())
	}
}
