// Package testocsp is a TEST ONLY OCSP responder over the test PKI in
// testdata/pki/ocsp: it answers good, revoked or unknown for the three
// signer certificates there, by file name. It accepts GET (base64 request
// in the path, as c2pa-rs sends) and POST.
package testocsp

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/ocsp"
)

// Addr is where the test signer certificates expect the responder.
const Addr = "127.0.0.1:8766"

// Responder answers OCSP requests for configured serial numbers. Serials it
// does not know get "unknown".
type Responder struct {
	Certs []*x509.Certificate // responder first, then its issuer
	Key   crypto.Signer
	// Now returns the time responses are produced; nil means time.Now.
	Now func() time.Time

	mu       sync.Mutex
	statuses map[string]ocsp.CertStatus
}

// SetStatus sets the answer for a serial number.
func (r *Responder) SetStatus(serial *big.Int, s ocsp.CertStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.statuses == nil {
		r.statuses = map[string]ocsp.CertStatus{}
	}
	r.statuses[serial.String()] = s
}

func (r *Responder) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Answer builds the response for one request.
func (r *Responder) Answer(req []byte) ([]byte, error) {
	ids, err := ocsp.ParseRequest(req)
	if err != nil {
		return nil, err
	}
	now := r.now().UTC().Truncate(time.Second)
	var singles []ocsp.Single
	r.mu.Lock()
	for _, id := range ids {
		st, ok := r.statuses[id.SerialNumber.String()]
		if !ok {
			st = ocsp.Unknown
		}
		s := ocsp.Single{CertID: id, Status: st, Reason: -1, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(7 * 24 * time.Hour)}
		if st == ocsp.Revoked {
			// Revoked well before any signature made with the test PKI.
			s.RevokedAt, s.Reason = r.Certs[0].NotBefore.Add(time.Minute), 1
		}
		singles = append(singles, s)
	}
	r.mu.Unlock()
	return ocsp.CreateResponse(r.Certs, r.Key, singles, now)
}

// ServeHTTP answers GET /<base64 request> and POST with the request body.
func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var body []byte
	switch req.Method {
	case http.MethodPost:
		b, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = b
	case http.MethodGet:
		p, err := url.PathUnescape(strings.TrimPrefix(req.URL.EscapedPath(), "/"))
		if err == nil {
			body, err = base64.StdEncoding.DecodeString(p)
		}
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := r.Answer(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(resp)
}

// Load reads the responder and the three signers from a PKI directory (its
// ocsp/ subdirectory) and sets their answers: good.pem good, revoked.pem
// revoked, unknown.pem unknown.
func Load(pkiDir string) (*Responder, error) {
	dir := filepath.Join(pkiDir, "ocsp")
	resp, err := readCert(filepath.Join(dir, "responder.pem"))
	if err != nil {
		return nil, err
	}
	inter, err := readCert(filepath.Join(pkiDir, "intermediate.pem"))
	if err != nil {
		return nil, err
	}
	key, err := readKey(filepath.Join(dir, "responder.key"))
	if err != nil {
		return nil, err
	}
	r := &Responder{Certs: []*x509.Certificate{resp, inter}, Key: key}
	for name, st := range map[string]ocsp.CertStatus{"good": ocsp.Good, "revoked": ocsp.Revoked, "unknown": ocsp.Unknown} {
		c, err := readCert(filepath.Join(dir, name+".pem"))
		if err != nil {
			return nil, err
		}
		r.SetStatus(c.SerialNumber, st)
	}
	return r, nil
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func readKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return s, nil
}
