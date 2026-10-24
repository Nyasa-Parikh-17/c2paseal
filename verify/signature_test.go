package verify

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

func activeManifest(t *testing.T, f fixtures.Fixture) *manifest.Manifest {
	t.Helper()
	b, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	var root *jumbf.Box
	if f.Format == "png" {
		st, err := png.Extract(b)
		if err != nil {
			t.Fatal(err)
		}
		root = st.Root
	} else {
		st, err := jpeg.Extract(b)
		if err != nil {
			t.Fatal(err)
		}
		root = st.Root
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return ms[len(ms)-1]
}

func testAnchors(t *testing.T) []*x509.Certificate {
	t.Helper()
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "pki", "trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// signatureCode reports whether a code is produced by Signature.
func signatureCode(code string) bool {
	return strings.HasPrefix(code, "claimSignature.") || strings.HasPrefix(code, "signingCredential.") ||
		strings.HasPrefix(code, "algorithm.") || code == ClaimMalformed
}

// group renders statuses as "kind: code @url" lines, keeping order.
func group(statuses []Status) []string {
	var out []string
	for _, k := range []Kind{Success, Informational, Failure} {
		for _, s := range statuses {
			if s.Kind() == k {
				out = append(out, fmt.Sprintf("%s: %s @%s", k, s.Code, s.URL))
			}
		}
	}
	return out
}

func oracleGroup(g *fixtures.StatusGroup) []string {
	var out []string
	for _, x := range []struct {
		k    Kind
		list []fixtures.Status
	}{{Success, g.Success}, {Informational, g.Informational}, {Failure, g.Failure}} {
		for _, s := range x.list {
			if signatureCode(s.Code) {
				out = append(out, fmt.Sprintf("%s: %s @%s", x.k, s.Code, s.URL))
			}
		}
	}
	return out
}

// TestOracle compares Signature with c2patool for every readable fixture,
// with default trust (test PKI untrusted) and with the test root trusted.
func TestOracle(t *testing.T) {
	all, err := fixtures.List()
	if err != nil {
		t.Fatal(err)
	}
	anchors := testAnchors(t)
	n := 0
	for _, f := range all {
		for _, mode := range []string{"default", "trusted"} {
			exp, err := f.Expected()
			opts := &Options{Now: corpusTime}
			if mode == "trusted" {
				exp, err = f.Trusted()
				opts.TrustAnchors = anchors
			}
			if err != nil {
				t.Fatal(err)
			}
			if exp.Failed() {
				continue
			}
			n++
			t.Run(f.String()+"/"+mode, func(t *testing.T) {
				m := activeManifest(t, f)
				got := group(Signature(m, nil, opts))
				want := oracleGroup(exp.ValidationResults.ActiveManifest)
				if !slices.Equal(got, want) {
					t.Errorf("statuses\n got  %q\n want %q", got, want)
				}
			})
		}
	}
	if n < 26 {
		t.Errorf("only %d fixture/mode pairs compared", n)
	}
}
