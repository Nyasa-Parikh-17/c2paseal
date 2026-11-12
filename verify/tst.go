package verify

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// A small reader for RFC 3161 time-stamp tokens (CMS SignedData, RFC 5652).
// It parses without verifying, so the time-stamp checks can tell a token
// that cannot be read (timeStamp.malformed) from one whose CMS signature
// does not verify (timeStamp.untrusted), as c2pa-rs does.

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

var errToken = errors.New("time-stamp token could not be parsed")

// tsToken is a parsed, unverified TimeStampToken.
type tsToken struct {
	hasCerts bool                // the certificates field is present
	certsOK  bool                // and every entry is an X.509 certificate
	certs    []*x509.Certificate // the embedded certificates
	content  []byte              // eContent: the DER TSTInfo
	signers  []signer
}

// signer is one SignerInfo.
type signer struct {
	sid         asn1.RawValue
	digestOID   asn1.ObjectIdentifier
	signedAttrs []byte // DER of the [0] IMPLICIT SignedAttributes, or nil
	attrs       []attribute
	signature   []byte
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// values returns the elements of an attribute's SET OF AttributeValue.
func (a attribute) values() []asn1.RawValue {
	out, _ := elements(a.Values.Bytes)
	return out
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContent     encapContent
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type encapContent struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds      int64 `asn1:"optional"`
	Milliseconds int64 `asn1:"tag:0,optional"`
	Microseconds int64 `asn1:"tag:1,optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	Time           time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// unmarshal decodes exactly one DER value.
func unmarshal(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errToken
	}
	return nil
}

// elements splits concatenated DER values.
func elements(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

// parseToken reads a TimeStampToken, or a TimeStampResp carrying one (as
// c2pa-rs accepts both). It fails only if the SignedData structure itself
// cannot be read.
func parseToken(b []byte) (*tsToken, error) {
	var top asn1.RawValue
	if err := unmarshal(b, &top); err != nil || top.Tag != asn1.TagSequence {
		return nil, errToken
	}
	inner, err := elements(top.Bytes)
	if err != nil || len(inner) == 0 {
		return nil, errToken
	}
	if inner[0].Tag == asn1.TagSequence { // TimeStampResp: PKIStatusInfo first
		// Granted (0) or grantedWithMods (1).
		status, err := elements(inner[0].Bytes)
		var code int
		if err != nil || len(inner) != 2 || len(status) == 0 || unmarshal(status[0].FullBytes, &code) != nil || (code != 0 && code != 1) {
			return nil, errToken
		}
		b = inner[1].FullBytes
	}
	var ci contentInfo
	if err := unmarshal(b, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return nil, errToken
	}
	var sd signedData
	if err := unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, errToken
	}
	t := &tsToken{}
	// encoding/asn1 keeps the explicit [0] wrapper in the RawValue.
	var ec asn1.RawValue
	if len(sd.EncapContent.EContent.Bytes) > 0 && unmarshal(sd.EncapContent.EContent.Bytes, &ec) == nil &&
		ec.Class == asn1.ClassUniversal && ec.Tag == asn1.TagOctetString && !ec.IsCompound {
		t.content = ec.Bytes
	}
	if len(sd.Certificates.FullBytes) > 0 {
		t.hasCerts, t.certsOK = true, true
		list, err := elements(sd.Certificates.Bytes)
		if err != nil {
			return nil, errToken
		}
		for _, c := range list {
			if c.Class != asn1.ClassUniversal || c.Tag != asn1.TagSequence {
				t.certsOK = false // another CertificateChoices alternative
				continue
			}
			cert, err := x509.ParseCertificate(c.FullBytes)
			if err != nil {
				return nil, errToken
			}
			t.certs = append(t.certs, cert)
		}
	}
	infos, err := elements(sd.SignerInfos.Bytes)
	if err != nil {
		return nil, errToken
	}
	for _, raw := range infos {
		var si signerInfo
		if err := unmarshal(raw.FullBytes, &si); err != nil {
			return nil, errToken
		}
		s := signer{sid: si.SID, digestOID: si.DigestAlgorithm.Algorithm, signature: si.Signature}
		if len(si.SignedAttrs.FullBytes) > 0 {
			s.signedAttrs = si.SignedAttrs.FullBytes
			list, err := elements(si.SignedAttrs.Bytes)
			if err != nil {
				return nil, errToken
			}
			for _, a := range list {
				var attr attribute
				if err := unmarshal(a.FullBytes, &attr); err != nil {
					return nil, errToken
				}
				s.attrs = append(s.attrs, attr)
			}
		}
		t.signers = append(t.signers, s)
	}
	return t, nil
}

// cert returns the embedded certificate named by the signer's identifier.
func (t *tsToken) cert(s signer) *x509.Certificate {
	for _, c := range t.certs {
		switch {
		case s.sid.Class == asn1.ClassUniversal && s.sid.Tag == asn1.TagSequence:
			var ias issuerAndSerial
			if unmarshal(s.sid.FullBytes, &ias) == nil && ias.Serial != nil &&
				bytes.Equal(ias.Issuer.FullBytes, c.RawIssuer) && ias.Serial.Cmp(c.SerialNumber) == 0 {
				return c
			}
		case s.sid.Class == asn1.ClassContextSpecific && s.sid.Tag == 0:
			if len(c.SubjectKeyId) > 0 && bytes.Equal(s.sid.Bytes, c.SubjectKeyId) {
				return c
			}
		}
	}
	return nil
}

// attr returns the signed attribute of the given type, or nil.
func (s signer) attr(oid asn1.ObjectIdentifier) *attribute {
	for i := range s.attrs {
		if s.attrs[i].Type.Equal(oid) {
			return &s.attrs[i]
		}
	}
	return nil
}

// signingTime returns the CMS signingTime attribute if it holds exactly
// one decodable time.
func (s signer) signingTime() (time.Time, bool) {
	a := s.attr(oidSigningTime)
	if a == nil {
		return time.Time{}, false
	}
	v := a.values()
	if len(v) != 1 {
		return time.Time{}, false
	}
	var t time.Time
	if unmarshal(v[0].FullBytes, &t) != nil {
		return time.Time{}, false
	}
	return t, true
}

// tbs is what the SignerInfo signature covers: the signed attributes
// re-tagged as a SET, or else the content itself.
func (s signer) tbs(content []byte) []byte {
	if s.signedAttrs == nil {
		return content
	}
	b := bytes.Clone(s.signedAttrs)
	b[0] = 0x31 // [0] IMPLICIT -> SET
	return b
}

// checkSigner validates one SignerInfo of a token against data, in the
// order of c2pa-rs verify_time_stamp. It returns the statuses, the time
// the token asserts, and whether it is valid up to (not including) the
// trust checks.
func (t *tsToken) checkSigner(s signer, cert *x509.Certificate, data []byte) (out []tsStatus, at time.Time, ok bool) {
	add := func(code, why string) { out = append(out, tsStatus{code, why}) }
	cn := cert.Subject.CommonName

	var info tstInfo
	if t.content == nil || unmarshal(t.content, &info) != nil {
		add(TimeStampMalformed, "timestamp response had no TstInfo")
		return out, at, false
	}
	at = info.Time

	if s.signedAttrs != nil {
		if st, ok := s.signingTime(); ok {
			at = st
		}
		md := s.attr(oidMessageDigest)
		if md == nil {
			add(TimeStampMalformed, "timestamp no message digest")
			return out, at, false
		}
		vals := md.values()
		if len(vals) != 1 {
			add(TimeStampMalformed, "timestamp response contained multiple message digests")
			return out, at, false
		}
		var want []byte
		if unmarshal(vals[0].FullBytes, &want) != nil {
			add(TimeStampMalformed, "timestamp could not decode signed message data")
			return out, at, false
		}
		h := digestAlg(s.digestOID)
		if h == 0 || !h.Available() {
			add(TimeStampMalformed, "timestamp bad message digest algorithm")
			return out, at, false
		}
		if !bytes.Equal(digest(h, t.content), want) {
			add(TimeStampMismatch, "timestamp bad message digest")
			return out, at, false
		}
	}

	if verifyCMS(cert, digestAlg(s.digestOID), s.tbs(t.content), s.signature) != nil {
		add(TimeStampUntrusted, "timestamp signed data did not match signature")
		return out, at, false
	}
	if at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
		add(TimeStampOutsideValidity, "timestamp signer outside of certificate validity")
		return out, at, false
	}
	h := digestAlg(info.MessageImprint.HashAlgorithm.Algorithm)
	if h == 0 || !h.Available() {
		add(TimeStampUntrusted, "timestamp unknown message digest algorithm")
		return out, at, false
	}
	if !bytes.Equal(digest(h, data), info.MessageImprint.HashedMessage) {
		add(TimeStampMismatch, "timestamp message digest did not match: "+cn)
		return out, at, false
	}
	add(TimeStampValidated, "timestamp message digest matched: "+cn)
	return out, at, true
}

// tsStatus is a time-stamp status before its URL is known.
type tsStatus struct{ code, why string }
