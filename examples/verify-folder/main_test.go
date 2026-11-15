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
	trust := filepath.Join(td, "pki", "trust-anchors.pem")
	signed := filepath.Join(td, "signed") // files signed with the TEST ONLY PKI

	var out bytes.Buffer
	ok, err := run([]string{"--trust", trust, "--require-trusted", signed}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.Contains(out.String(), "Trusted") {
		t.Errorf("signed folder: ok %v\n%s", ok, out.String())
	}

	out.Reset()
	ok, err = run([]string{filepath.Join(td, "unsigned")}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if ok || !strings.Contains(out.String(), "FAIL Invalid") {
		t.Errorf("unsigned folder: ok %v\n%s", ok, out.String())
	}
}
