// Command genocsppki adds the OCSP part of the TEST ONLY PKI: an OCSP
// responder and three claim signers whose certificates point at a local
// responder, all issued by the existing test intermediate. The other test
// keys are not touched.
//
//	go run ./scripts/genocsppki testdata/pki
//
// It writes, under <pki>/ocsp/:
//
//	responder.pem / .key        OCSP signing (id-kp-OCSPSigning)
//	good.pem, revoked.pem, unknown.pem (+ .key, -chain.pem)
//	                            claim signers with AIA OCSP http://127.0.0.1:8766/;
//	                            internal/testocsp answers good, revoked and
//	                            unknown for them
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ResponderURL is the OCSP URL in the signer certificates.
const ResponderURL = "http://127.0.0.1:8766/"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genocsppki <pki-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "genocsppki:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	inter, err := readCert(filepath.Join(dir, "intermediate.pem"))
	if err != nil {
		return err
	}
	interKey, err := readKey(filepath.Join(dir, "intermediate.key"))
	if err != nil {
		return err
	}
	out := filepath.Join(dir, "ocsp")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	from := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	to := from.AddDate(5, 0, 0)

	if err := issue(out, "responder", &x509.Certificate{
		Subject:     pkix.Name{CommonName: "C2paSeal Test OCSP Responder", Organization: []string{"C2paSeal TEST ONLY"}},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}, from, to, inter, interKey); err != nil {
		return err
	}
	for _, name := range []string{"good", "revoked", "unknown"} {
		if err := issue(out, name, &x509.Certificate{
			Subject:            pkix.Name{CommonName: "C2paSeal Test Signer (OCSP " + name + ")", Organization: []string{"C2paSeal TEST ONLY"}},
			KeyUsage:           x509.KeyUsageDigitalSignature,
			ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}}, // documentSigning
			OCSPServer:         []string{ResponderURL},
		}, from, to, inter, interKey); err != nil {
			return err
		}
	}
	return nil
}

func issue(dir, name string, tmpl *x509.Certificate, from, to time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(pub, &spki); err != nil {
		return err
	}
	ski := sha1.Sum(spki.Key.Bytes)
	tmpl.SerialNumber = serial
	tmpl.NotBefore, tmpl.NotAfter = from, to
	tmpl.BasicConstraintsValid = true
	tmpl.SubjectKeyId = ski[:]
	tmpl.AuthorityKeyId = parent.SubjectKeyId
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name+".pem"), certPEM, 0o644); err != nil {
		return err
	}
	chain := append(append([]byte(nil), certPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})...)
	if err := os.WriteFile(filepath.Join(dir, name+"-chain.pem"), chain, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o644)
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

func readKey(path string) (*ecdsa.PrivateKey, error) {
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
		if ec, err2 := x509.ParseECPrivateKey(blk.Bytes); err2 == nil {
			return ec, nil
		}
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ec, nil
}
