// Package testtsa is an offline RFC 3161 time-stamp authority for tests and
// the interop harness. Its certificate is issued by the TEST ONLY root in
// testdata/pki, so validators that trust that root also trust its tokens.
// Never use it for anything real: the root's private key is public.
package testtsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/digitorus/timestamp"
)

// TSA is an http.Handler answering RFC 3161 time-stamp requests. The fields
// after Cert and Key select misbehaviour for tests; set them before serving.
type TSA struct {
	Cert *x509.Certificate
	Key  crypto.Signer

	At        func() time.Time // genTime; nil means now
	Status    int              // HTTP status; 0 means 200
	Reject    bool             // answer with a rejection PKIStatus
	NoCerts   bool             // leave the TSA certificate out of the token
	BadDigest bool             // time-stamp other data
	BadNonce  bool             // echo a different nonce
	SerialLen int              // serial number size in bytes; 0 means 8

	requests atomic.Int64
}

// New creates a TSA with a fresh key and a certificate issued by root.pem /
// root.key in pkiDir.
func New(pkiDir string) (*TSA, error) {
	read := func(name string) (*pem.Block, error) {
		b, err := os.ReadFile(filepath.Join(pkiDir, name))
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("testtsa: no PEM block in %s", name)
		}
		return blk, nil
	}
	blk, err := read("root.pem")
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("testtsa: root: %w", err)
	}
	if blk, err = read("root.key"); err != nil {
		return nil, err
	}
	rootKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("testtsa: root key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "C2paSeal Test TSA", Organization: []string{"C2paSeal TEST ONLY"}},
		NotBefore:    root.NotBefore,
		NotAfter:     root.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("testtsa: issue certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &TSA{Cert: cert, Key: key}, nil
}

// Requests returns how many requests the TSA has received.
func (f *TSA) Requests() int { return int(f.requests.Load()) }

// ServeHTTP answers one time-stamp request.
func (f *TSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	if f.Status != 0 {
		http.Error(w, "unavailable", f.Status)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req, err := timestamp.ParseRequest(body)
	if err != nil || r.Header.Get("Content-Type") != "application/timestamp-query" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := f.respond(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Write(resp)
}

func (f *TSA) respond(req *timestamp.Request) ([]byte, error) {
	if f.Reject {
		return timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadRequest)
	}
	if req.HashAlgorithm == 0 {
		return nil, errors.New("no hash algorithm")
	}
	at := time.Now()
	if f.At != nil {
		at = f.At()
	}
	serialLen := f.SerialLen
	if serialLen == 0 {
		serialLen = 8
	}
	ts := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              at.UTC().Truncate(time.Second),
		Nonce:             req.Nonce,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      new(big.Int).Lsh(big.NewInt(1), uint(8*serialLen-1)),
		AddTSACertificate: !f.NoCerts,
	}
	if f.BadDigest {
		ts.HashedMessage = make([]byte, len(req.HashedMessage))
	}
	if f.BadNonce {
		ts.Nonce = big.NewInt(7)
	}
	return ts.CreateResponseWithOpts(f.Cert, f.Key, crypto.SHA256)
}
