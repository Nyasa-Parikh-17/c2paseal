package sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/testocsp"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// inProcess answers HTTP requests with a handler, without a network port.
type inProcess struct{ h http.Handler }

func (p inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Body = io.NopCloser(bytes.NewReader(rec.Body.Bytes()))
	return resp, nil
}

func ocspSigner(t *testing.T, name string) *Options {
	t.Helper()
	dir, _ := fixtures.Dir()
	chain, key := loadPair(t, filepath.Join(dir, "pki", "ocsp", name+"-chain.pem"), filepath.Join(dir, "pki", "ocsp", name+".key"))
	return &Options{Chain: chain, Signer: key}
}

// loadPair reads a PEM chain and a PKCS #8 key.
func loadPair(t *testing.T, chainPath, keyPath string) ([]*x509.Certificate, crypto.Signer) {
	t.Helper()
	b, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(kb)
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return chain, key.(crypto.Signer)
}

func responder(t *testing.T) *testocsp.Responder {
	t.Helper()
	dir, _ := fixtures.Dir()
	r, err := testocsp.Load(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func activeOf(t *testing.T, file []byte) *manifest.Manifest {
	t.Helper()
	_, root, err := asset.Extract(file)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return ms[len(ms)-1]
}

// TestStaple: the responder's answer is stored in rVals, with and without a
// time-stamp, and the store keeps its reserved size.
func TestStaple(t *testing.T) {
	r := responder(t)
	client := &http.Client{Transport: inProcess{r}}
	in := unsignedFile(t, "small.jpg")
	for _, name := range []string{"good", "revoked", "unknown"} {
		opts := ocspSigner(t, name)
		opts.FetchOCSP, opts.OCSPClient = true, client
		out, err := JPEG(in, opts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := activeOf(t, out)
		if len(m.Signature.OCSP) != 1 {
			t.Fatalf("%s: %d stapled responses", name, len(m.Signature.OCSP))
		}
		// The same response passed in directly gives the same header.
		opts2 := ocspSigner(t, name)
		opts2.OCSPResponse = m.Signature.OCSP[0]
		out2, err := JPEG(in, opts2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(activeOf(t, out2).Signature.OCSP[0], m.Signature.OCSP[0]) {
			t.Errorf("%s: OCSPResponse not stapled as given", name)
		}
	}

	// With a time-stamp: the slot keeps its size around rVals.
	_, tsa := newFakeTSA(t)
	opts := ocspSigner(t, "good")
	opts.FetchOCSP, opts.OCSPClient, opts.TSAURL, opts.TSAClient = true, client, tsa.URL, tsa.Client()
	out, err := JPEG(in, opts)
	if err != nil {
		t.Fatal(err)
	}
	if m := activeOf(t, out); len(m.Signature.OCSP) != 1 || len(m.Signature.Timestamps) != 1 {
		t.Errorf("time-stamped: %d responses, %d tokens", len(m.Signature.OCSP), len(m.Signature.Timestamps))
	}
}

func TestStapleErrors(t *testing.T) {
	r := responder(t)
	client := &http.Client{Transport: inProcess{r}}
	in := unsignedFile(t, "small.jpg")
	good := ocspSigner(t, "good")
	good.FetchOCSP, good.OCSPClient = true, client
	out, err := JPEG(in, good)
	if err != nil {
		t.Fatal(err)
	}
	goodResp := activeOf(t, out).Signature.OCSP[0]

	chain, key := testPKI(t) // no OCSP URL
	for name, opts := range map[string]*Options{
		"garbage":            {Chain: ocspSigner(t, "good").Chain, Signer: ocspSigner(t, "good").Signer, OCSPResponse: []byte{1, 2, 3}},
		"another signer's":   {Chain: ocspSigner(t, "revoked").Chain, Signer: ocspSigner(t, "revoked").Signer, OCSPResponse: goodResp},
		"no OCSP URL":        {Chain: chain, Signer: key, FetchOCSP: true, OCSPClient: client},
		"no issuer in chain": {Chain: chain[:1], Signer: key, FetchOCSP: true, OCSPClient: client},
		"responder down": {Chain: ocspSigner(t, "good").Chain, Signer: ocspSigner(t, "good").Signer, FetchOCSP: true,
			OCSPClient: &http.Client{Transport: inProcess{http.NotFoundHandler()}}},
	} {
		if _, err := JPEG(in, opts); !errors.Is(err, ErrBadOCSP) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// render lists a c2patool or C2paSeal result as "kind code" lines in
// c2patool's grouping.
func renderReport(t *testing.T, b []byte) (state string, lines []string) {
	t.Helper()
	var rep struct {
		State   string `json:"validation_state"`
		Results struct {
			Active map[string][]verify.Status `json:"activeManifest"`
		} `json:"validation_results"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	for _, k := range []string{"success", "informational", "failure"} {
		for _, s := range rep.Results.Active[k] {
			lines = append(lines, k+" "+s.Code+" @"+s.URL)
		}
	}
	return rep.State, lines
}

func renderOurs(r *verify.Result) (string, []string) {
	var lines []string
	for _, k := range []verify.Kind{verify.Success, verify.Informational, verify.Failure} {
		for _, s := range r.ActiveManifest {
			if s.Kind() == k {
				lines = append(lines, fmt.Sprint(k)+" "+s.Code+" @"+s.URL)
			}
		}
	}
	return string(r.State()), lines
}

// TestC2patoolOCSP: c2patool and C2paSeal agree on the good, revoked and
// unknown signers, with the response stapled by our signer and, with
// online checks turned on in both, fetched from the test responder.
func TestC2patoolOCSP(t *testing.T) {
	needC2patool(t)
	anchors := anchors(t)
	r := responder(t)
	l, err := net.Listen("tcp", testocsp.Addr)
	if err != nil {
		t.Skipf("cannot listen on %s for the test responder: %v", testocsp.Addr, err)
	}
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	fetchSettings := filepath.Join(t.TempDir(), "fetch.toml")
	if err := os.WriteFile(fetchSettings, []byte("[verify]\nocsp_fetch = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := unsignedFile(t, "small.jpg")
	for _, name := range []string{"good", "revoked", "unknown"} {
		for _, staple := range []bool{true, false} {
			opts := ocspSigner(t, name)
			opts.FetchOCSP = staple
			out, err := JPEG(in, opts)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), name+".jpg")
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("c2patool", path, "trust", "--trust_anchors", "../testdata/pki/trust-anchors.pem") // relative: c2patool reads C:/ as a URL
			if !staple {
				cmd.Env = append(os.Environ(), "C2PATOOL_SETTINGS="+fetchSettings)
			}
			b, cerr := cmd.Output()
			ours := verify.File(out, &verify.Options{TrustAnchors: anchors, FetchOCSP: !staple})
			label := fmt.Sprintf("%s stapled=%v", name, staple)
			if cerr != nil {
				// c2patool refuses the file: we give exactly one failure.
				if len(ours.ActiveManifest) != 1 || ours.ActiveManifest[0].Kind() != verify.Failure {
					t.Errorf("%s: c2patool failed (%v); ours %+v", label, cerr, ours.ActiveManifest)
				}
				t.Logf("%s: c2patool error; ours %s", label, ours.ActiveManifest[0].Code)
				continue
			}
			wantState, want := renderReport(t, b)
			gotState, got := renderOurs(ours)
			if gotState != wantState || !slices.Equal(got, want) {
				t.Errorf("%s:\n got  %s %q\n want %s %q", label, gotState, got, wantState, want)
			}
			t.Logf("%s: %s", label, gotState)
		}
	}
}
