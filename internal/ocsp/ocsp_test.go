package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func cert(t *testing.T, cn string, serial int64, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, eku []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: ca, BasicConstraintsValid: true, ExtKeyUsage: eku,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func TestRoundTrip(t *testing.T) {
	ca, caKey := cert(t, "CA", 1, nil, nil, true, nil)
	leaf, _ := cert(t, "Leaf", 2, ca, caKey, false, nil)
	other, _ := cert(t, "Other", 3, ca, caKey, false, nil)
	resp, respKey := cert(t, "Responder", 4, ca, caKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})

	req, err := CreateRequest(leaf, ca)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := ParseRequest(req)
	if err != nil || len(ids) != 1 || !ids[0].Matches(leaf, ca) || ids[0].Matches(other, ca) || ids[0].Matches(leaf, leaf) {
		t.Fatalf("request: %v %+v", err, ids)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for _, want := range []Single{
		{CertID: ids[0], Status: Good, Reason: -1, ThisUpdate: now, NextUpdate: now.Add(time.Hour)},
		{CertID: ids[0], Status: Revoked, RevokedAt: now.Add(-time.Minute), Reason: 1, ThisUpdate: now},
		{CertID: ids[0], Status: Revoked, RevokedAt: now.Add(-time.Minute), Reason: -1, ThisUpdate: now},
		{CertID: ids[0], Status: Unknown, Reason: -1, ThisUpdate: now},
	} {
		der, err := CreateResponse([]*x509.Certificate{resp, ca}, respKey, []Single{want}, now)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseResponse(der)
		if err != nil {
			t.Fatalf("%v: %v", want.Status, err)
		}
		if err := r.CheckSignature(); err != nil {
			t.Errorf("%v: %v", want.Status, err)
		}
		got := r.Responses[0]
		if len(r.Responses) != 1 || got.Status != want.Status || got.Reason != want.Reason || !got.RevokedAt.Equal(want.RevokedAt) ||
			!got.ThisUpdate.Equal(want.ThisUpdate) || !got.NextUpdate.Equal(want.NextUpdate) || !got.CertID.Matches(leaf, ca) ||
			len(r.Certs) != 2 || !r.ProducedAt.Equal(now) {
			t.Errorf("%v: got %+v", want.Status, got)
		}
		// A changed byte in the signed data breaks the signature.
		r.TBS = append([]byte(nil), r.TBS...)
		r.TBS[len(r.TBS)-1] ^= 1
		if err := r.CheckSignature(); !errors.Is(err, ErrSignature) {
			t.Errorf("tampered: %v", err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, b := range [][]byte{nil, {0x30, 0x00}, {0x30, 0x03, 0x0a, 0x01, 0x00}, {0xff}} {
		if _, err := ParseResponse(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("% x: %v", b, err)
		}
	}
	// tryLater (3): no response bytes, not an error.
	if r, err := ParseResponse([]byte{0x30, 0x03, 0x0a, 0x01, 0x03}); err != nil || r.Status != 3 {
		t.Errorf("tryLater: %v %+v", err, r)
	}
	if _, err := ParseRequest([]byte{0x30, 0x00}); !errors.Is(err, ErrMalformed) {
		t.Error("empty request")
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x0a, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseResponse(b)
		if err == nil {
			_ = r.CheckSignature()
		}
		_, _ = ParseRequest(b)
	})
}

func TestFetch(t *testing.T) {
	ca, caKey := cert(t, "CA", 1, nil, nil, true, nil)
	resp, respKey := cert(t, "Responder", 4, ca, caKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	var lastMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.Method
		p, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/"))
		req, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		ids, err := ParseRequest(req)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		b, _ := CreateResponse([]*x509.Certificate{resp, ca}, respKey, []Single{{CertID: ids[0], Status: Good, Reason: -1, ThisUpdate: time.Now()}}, time.Now())
		w.Write(b)
	}))
	defer srv.Close()

	leaf, _ := cert(t, "Leaf", 2, ca, caKey, false, nil)
	leaf.OCSPServer = []string{srv.URL + "/missing-first", srv.URL}
	// The first URL answers 400 (its path is not a request), the second 200.
	der, err := Fetch(srv.Client(), leaf, ca)
	if err != nil || lastMethod != http.MethodGet {
		t.Fatalf("Fetch: %v (%s)", err, lastMethod)
	}
	r, err := ParseResponse(der)
	if err != nil {
		t.Fatal(err)
	}
	if s := r.Find(leaf, ca); s == nil || s.Status != Good {
		t.Errorf("Find: %+v", s)
	}
	other, _ := cert(t, "Other", 3, ca, caKey, false, nil)
	if r.Find(other, ca) != nil {
		t.Error("Find matched another certificate")
	}
	leaf.OCSPServer = nil
	if _, err := Fetch(srv.Client(), leaf, ca); !errors.Is(err, ErrFetch) {
		t.Errorf("no URL: %v", err)
	}
	leaf.OCSPServer = []string{"http://127.0.0.1:1/"}
	if _, err := Fetch(srv.Client(), leaf, ca); !errors.Is(err, ErrFetch) {
		t.Errorf("unreachable: %v", err)
	}
	if CertStatus(2).String() != "unknown" {
		t.Error("String")
	}
}
