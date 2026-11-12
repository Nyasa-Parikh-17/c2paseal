package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
)

// Signature algorithms are verified with the standard library only. Signing
// stays ES256; the others are read so that files from other tools (C2PA 1.x
// corpora are mostly PS256) can be validated.

// coseAlg describes a COSE signature algorithm C2PA allows (C2PA 2.4 §13.2).
type coseAlg struct {
	hash  crypto.Hash
	kind  keyKind
	curve elliptic.Curve // for ECDSA
}

type keyKind int

const (
	keyEC keyKind = iota
	keyRSAPSS
	keyEd25519
)

var coseAlgs = map[int64]coseAlg{
	cose.AlgES256:   {crypto.SHA256, keyEC, elliptic.P256()},
	cose.AlgES384:   {crypto.SHA384, keyEC, elliptic.P384()},
	cose.AlgES512:   {crypto.SHA512, keyEC, elliptic.P521()},
	cose.AlgPS256:   {crypto.SHA256, keyRSAPSS, nil},
	cose.AlgPS384:   {crypto.SHA384, keyRSAPSS, nil},
	cose.AlgPS512:   {crypto.SHA512, keyRSAPSS, nil},
	cose.AlgEd25519: {0, keyEd25519, nil},
}

// isEC reports whether alg is one of the ECDSA algorithms.
func isEC(alg int64) bool { a, ok := coseAlgs[alg]; return ok && a.kind == keyEC }

var errBadSignature = errors.New("signature does not verify")

// verifyCOSE checks a COSE signature (raw r|s for ECDSA, RSASSA-PSS with a
// salt as long as the digest, or Ed25519) over tbs with the key pub.
func verifyCOSE(alg int64, pub any, tbs, sig []byte) error {
	a, ok := coseAlgs[alg]
	if !ok {
		return errBadSignature
	}
	switch a.kind {
	case keyEC:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != a.curve {
			return errBadSignature
		}
		n := (a.curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return errBadSignature
		}
		r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(k, digest(a.hash, tbs), r, s) {
			return errBadSignature
		}
	case keyRSAPSS:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errBadSignature
		}
		if rsa.VerifyPSS(k, a.hash, digest(a.hash, tbs), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
			return errBadSignature
		}
	case keyEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, tbs, sig) {
			return errBadSignature
		}
	}
	return nil
}

func digest(h crypto.Hash, b []byte) []byte {
	d := h.New()
	d.Write(b)
	return d.Sum(nil)
}

var (
	oidRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

// publicKey returns a certificate's public key. Go's x509 does not parse
// RSASSA-PSS keys (id-RSASSA-PSS), which C2PA signers use; their key is the
// same PKCS #1 RSAPublicKey, so it is read here. pss reports such a key.
func publicKey(cert *x509.Certificate) (pub any, pss bool) {
	if cert.PublicKey != nil {
		return cert.PublicKey, false
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) > 0 {
		return nil, false
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSAPSS) {
		return nil, false
	}
	k, err := x509.ParsePKCS1PublicKey(spki.Key.RightAlign())
	if err != nil {
		return nil, false
	}
	return k, true
}

// Digest algorithm identifiers used in RFC 3161 tokens.
var digestOIDs = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, crypto.SHA1},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, crypto.SHA256},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, crypto.SHA384},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, crypto.SHA512},
}

// digestAlg maps a digest OID to a hash, or 0.
func digestAlg(oid asn1.ObjectIdentifier) crypto.Hash {
	for _, d := range digestOIDs {
		if d.oid.Equal(oid) {
			return d.hash
		}
	}
	return 0
}

// verifyCMS checks a CMS SignerInfo signature the way c2pa-rs does
// (validator_for_sig_and_hash_algs): the scheme follows the signer's key
// type, the hash the SignerInfo digest algorithm. ECDSA signatures are DER.
func verifyCMS(cert *x509.Certificate, h crypto.Hash, tbs, sig []byte) error {
	if h == 0 || h == crypto.SHA1 {
		return errBadSignature
	}
	pub, pss := publicKey(cert)
	d := digest(h, tbs)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if pss {
			return rsa.VerifyPSS(k, h, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(k, h, d, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, d, sig) {
			return errBadSignature
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, tbs, sig) {
			return errBadSignature
		}
		return nil
	}
	return errBadSignature
}
