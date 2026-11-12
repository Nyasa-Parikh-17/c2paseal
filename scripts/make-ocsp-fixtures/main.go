// Command make-ocsp-fixtures signs testdata/unsigned/small.jpg with each
// OCSP test signer (testdata/pki/ocsp) and staples the TEST ONLY
// responder's answer (internal/testocsp, in process: no network) in the
// COSE unprotected header:
//
//	go run ./scripts/make-ocsp-fixtures testdata
//
// It writes testdata/ocsp/{good,revoked,unknown}.jpg. Run scripts/oracle
// on testdata/ocsp afterwards (make-ocsp-fixtures.sh does both).
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/testocsp"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: make-ocsp-fixtures <testdata>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "make-ocsp-fixtures:", err)
		os.Exit(1)
	}
}

// local answers every request with the in-process responder.
type local struct{ h http.Handler }

func (l local) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	l.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Body = io.NopCloser(bytes.NewReader(rec.Body.Bytes()))
	return resp, nil
}

func run(td string) error {
	pki := filepath.Join(td, "pki")
	responder, err := testocsp.Load(pki)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: local{responder}}
	in, err := os.ReadFile(filepath.Join(td, "unsigned", "small.jpg"))
	if err != nil {
		return err
	}
	out := filepath.Join(td, "ocsp")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"good", "revoked", "unknown"} {
		chain, key, err := c2paseal.LoadSigner(filepath.Join(pki, "ocsp", name+"-chain.pem"), filepath.Join(pki, "ocsp", name+".key"))
		if err != nil {
			return err
		}
		signed, err := sign.JPEG(in, &sign.Options{
			Chain: chain, Signer: key,
			FetchOCSP: true, OCSPClient: client,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		path := filepath.Join(out, name+".jpg")
		if err := os.WriteFile(path, signed, 0o644); err != nil {
			return err
		}
		fmt.Println("signed:", path)
	}
	return nil
}
