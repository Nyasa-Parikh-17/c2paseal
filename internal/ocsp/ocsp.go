// Package ocsp reads and writes the parts of RFC 6960 OCSP that C2PA uses:
// responses stapled in a COSE header or fetched from a responder, and the
// requests that fetch them. Test responders also use it to write responses.
// Only the Go standard library is used.
package ocsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors.
var (
	ErrMalformed = errors.New("ocsp: malformed")
	ErrSignature = errors.New("ocsp: response signature does not verify")
)

// CertStatus is a certificate's status in a single response.
type CertStatus int

const (
	Good CertStatus = iota
	Revoked
	Unknown
)

func (s CertStatus) String() string {
	return [...]string{"good", "revoked", "unknown"}[s]
}

// ReasonRemoveFromCRL is CRLReason removeFromCRL (8).
const ReasonRemoveFromCRL = 8

// CertID names a certificate by its issuer and serial number.
type CertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// Single is one SingleResponse.
type Single struct {
	CertID     CertID
	Status     CertStatus
	RevokedAt  time.Time // Revoked only
	Reason     int       // CRLReason; -1 if absent
	ThisUpdate time.Time
	NextUpdate time.Time // zero if absent
}

// Response is a parsed OCSPResponse. For a successful response the basic
// response fields are filled in.
type Response struct {
	Status     int // OCSPResponseStatus; 0 is successful
	TBS        []byte
	SigAlg     pkix.AlgorithmIdentifier
	Signature  []byte
	Certs      []*x509.Certificate
	ProducedAt time.Time
	Responses  []Single
}

var (
	oidBasic  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

func hashFor(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	}
	return 0
}

// Signature algorithms a response may use.
var sigAlgs = []struct {
	oid asn1.ObjectIdentifier
	alg x509.SignatureAlgorithm
}{
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, x509.SHA256WithRSA},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, x509.SHA384WithRSA},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, x509.SHA512WithRSA},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, x509.ECDSAWithSHA256},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, x509.ECDSAWithSHA384},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, x509.ECDSAWithSHA512},
	{asn1.ObjectIdentifier{1, 3, 101, 112}, x509.PureEd25519},
}

func sigAlgFor(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	for _, s := range sigAlgs {
		if s.oid.Equal(oid) {
			return s.alg
		}
	}
	return x509.UnknownSignatureAlgorithm
}

// --- DER helpers -------------------------------------------------------------

func parseOne(b []byte) (asn1.RawValue, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return v, err
	}
	if len(rest) > 0 {
		return v, ErrMalformed
	}
	return v, nil
}

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

func isContext(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassContextSpecific && v.Tag == tag
}

func isUniversal(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag
}

func unmarshal(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return ErrMalformed
	}
	return nil
}

func malformed(what string, err error) error {
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMalformed, what, err)
	}
	return fmt.Errorf("%w: %s", ErrMalformed, what)
}

// --- parsing ---------------------------------------------------------------

// ParseResponse parses a DER OCSPResponse without verifying it.
func ParseResponse(der []byte) (*Response, error) {
	top, err := parseOne(der)
	if err != nil || !isUniversal(top, asn1.TagSequence) {
		return nil, malformed("OCSPResponse", err)
	}
	parts, err := elements(top.Bytes)
	if err != nil || len(parts) == 0 || !isUniversal(parts[0], asn1.TagEnum) {
		return nil, malformed("responseStatus", err)
	}
	var status asn1.Enumerated
	if err := unmarshal(parts[0].FullBytes, &status); err != nil {
		return nil, malformed("responseStatus", err)
	}
	r := &Response{Status: int(status)}
	if r.Status != 0 {
		return r, nil
	}
	if len(parts) != 2 || !isContext(parts[1], 0) {
		return nil, malformed("responseBytes", nil)
	}
	var rb struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}
	if err := unmarshal(parts[1].Bytes, &rb); err != nil {
		return nil, malformed("responseBytes", err)
	}
	if !rb.Type.Equal(oidBasic) {
		return nil, malformed("response type is not basic", nil)
	}
	return r, r.parseBasic(rb.Response)
}

func (r *Response) parseBasic(b []byte) error {
	top, err := parseOne(b)
	if err != nil || !isUniversal(top, asn1.TagSequence) {
		return malformed("BasicOCSPResponse", err)
	}
	parts, err := elements(top.Bytes)
	if err != nil || len(parts) < 3 {
		return malformed("BasicOCSPResponse", err)
	}
	r.TBS = parts[0].FullBytes
	if err := unmarshal(parts[1].FullBytes, &r.SigAlg); err != nil {
		return malformed("signatureAlgorithm", err)
	}
	var sig asn1.BitString
	if err := unmarshal(parts[2].FullBytes, &sig); err != nil {
		return malformed("signature", err)
	}
	r.Signature = sig.RightAlign()
	if len(parts) > 3 {
		if !isContext(parts[3], 0) {
			return malformed("certs", nil)
		}
		seq, err := parseOne(parts[3].Bytes)
		if err != nil || !isUniversal(seq, asn1.TagSequence) {
			return malformed("certs", err)
		}
		list, err := elements(seq.Bytes)
		if err != nil {
			return malformed("certs", err)
		}
		for _, c := range list {
			cert, err := x509.ParseCertificate(c.FullBytes)
			if err != nil {
				return malformed("certificate", err)
			}
			r.Certs = append(r.Certs, cert)
		}
	}
	return r.parseTBS()
}

func (r *Response) parseTBS() error {
	top, err := parseOne(r.TBS)
	if err != nil || !isUniversal(top, asn1.TagSequence) {
		return malformed("ResponseData", err)
	}
	parts, err := elements(top.Bytes)
	if err != nil {
		return malformed("ResponseData", err)
	}
	i := 0
	if i < len(parts) && isContext(parts[i], 0) { // version
		i++
	}
	if i < len(parts) && (isContext(parts[i], 1) || isContext(parts[i], 2)) { // responderID
		i++
	} else {
		return malformed("responderID", nil)
	}
	if i >= len(parts) {
		return malformed("producedAt", nil)
	}
	if err := unmarshal(parts[i].FullBytes, &r.ProducedAt); err != nil {
		return malformed("producedAt", err)
	}
	i++
	if i >= len(parts) || !isUniversal(parts[i], asn1.TagSequence) {
		return malformed("responses", nil)
	}
	list, err := elements(parts[i].Bytes)
	if err != nil {
		return malformed("responses", err)
	}
	for _, s := range list {
		single, err := parseSingle(s.FullBytes)
		if err != nil {
			return err
		}
		r.Responses = append(r.Responses, single)
	}
	return nil
}

func parseSingle(b []byte) (Single, error) {
	s := Single{Reason: -1}
	top, err := parseOne(b)
	if err != nil || !isUniversal(top, asn1.TagSequence) {
		return s, malformed("SingleResponse", err)
	}
	parts, err := elements(top.Bytes)
	if err != nil || len(parts) < 3 {
		return s, malformed("SingleResponse", err)
	}
	if err := unmarshal(parts[0].FullBytes, &s.CertID); err != nil {
		return s, malformed("certID", err)
	}
	st := parts[1]
	switch {
	case isContext(st, 0):
		s.Status = Good
	case isContext(st, 1):
		s.Status = Revoked
		inner, err := elements(st.Bytes)
		if err != nil || len(inner) == 0 {
			return s, malformed("revokedInfo", err)
		}
		if err := unmarshal(inner[0].FullBytes, &s.RevokedAt); err != nil {
			return s, malformed("revocationTime", err)
		}
		if len(inner) > 1 && isContext(inner[1], 0) {
			var reason asn1.Enumerated
			if err := unmarshal(inner[1].Bytes, &reason); err != nil {
				return s, malformed("revocationReason", err)
			}
			s.Reason = int(reason)
		}
	case isContext(st, 2):
		s.Status = Unknown
	default:
		return s, malformed("certStatus", nil)
	}
	if err := unmarshal(parts[2].FullBytes, &s.ThisUpdate); err != nil {
		return s, malformed("thisUpdate", err)
	}
	for _, p := range parts[3:] {
		if isContext(p, 0) {
			if err := unmarshal(p.Bytes, &s.NextUpdate); err != nil {
				return s, malformed("nextUpdate", err)
			}
		}
	}
	return s, nil
}

// CheckSignature verifies the response signature with the first embedded
// certificate, as c2pa-rs does.
func (r *Response) CheckSignature() error {
	if len(r.Certs) == 0 {
		return fmt.Errorf("%w: no responder certificate", ErrSignature)
	}
	alg := sigAlgFor(r.SigAlg.Algorithm)
	if alg == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("%w: unsupported algorithm %v", ErrSignature, r.SigAlg.Algorithm)
	}
	if err := r.Certs[0].CheckSignature(alg, r.TBS, r.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return nil
}

// Matches reports whether the CertID names cert as issued by issuer.
func (id CertID) Matches(cert, issuer *x509.Certificate) bool {
	if id.SerialNumber == nil || id.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}
	h := hashFor(id.HashAlgorithm.Algorithm)
	if h == 0 || !h.Available() {
		return false
	}
	name, key, ok := issuerHashes(h, issuer)
	return ok && bytes.Equal(name, id.IssuerNameHash) && bytes.Equal(key, id.IssuerKeyHash)
}

// issuerHashes hashes the issuer's subject name and public key bits.
func issuerHashes(h crypto.Hash, issuer *x509.Certificate) (name, key []byte, ok bool) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if unmarshal(issuer.RawSubjectPublicKeyInfo, &spki) != nil {
		return nil, nil, false
	}
	d := h.New()
	d.Write(issuer.RawSubject)
	name = d.Sum(nil)
	d = h.New()
	d.Write(spki.Key.RightAlign())
	return name, d.Sum(nil), true
}

// NewCertID returns the SHA-1 CertID of cert (the usual choice).
func NewCertID(cert, issuer *x509.Certificate) (CertID, error) {
	name, key, ok := issuerHashes(crypto.SHA1, issuer)
	if !ok {
		return CertID{}, malformed("issuer public key", nil)
	}
	return CertID{
		HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue},
		IssuerNameHash: name,
		IssuerKeyHash:  key,
		SerialNumber:   cert.SerialNumber,
	}, nil
}

// --- requests ----------------------------------------------------------------

// CreateRequest returns a DER OCSPRequest for cert.
func CreateRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	id, err := NewCertID(cert, issuer)
	if err != nil {
		return nil, err
	}
	type request struct{ ReqCert CertID }
	type tbsRequest struct{ RequestList []request }
	return asn1.Marshal(struct{ TBSRequest tbsRequest }{tbsRequest{[]request{{id}}}})
}

// ParseRequest returns the CertIDs an OCSPRequest asks about.
func ParseRequest(der []byte) ([]CertID, error) {
	top, err := parseOne(der)
	if err != nil || !isUniversal(top, asn1.TagSequence) {
		return nil, malformed("OCSPRequest", err)
	}
	parts, err := elements(top.Bytes)
	if err != nil || len(parts) == 0 {
		return nil, malformed("OCSPRequest", err)
	}
	tbs, err := elements(parts[0].Bytes)
	if err != nil {
		return nil, malformed("TBSRequest", err)
	}
	for _, p := range tbs {
		if !isUniversal(p, asn1.TagSequence) {
			continue // version, requestorName, extensions
		}
		reqs, err := elements(p.Bytes)
		if err != nil {
			return nil, malformed("requestList", err)
		}
		var out []CertID
		for _, rq := range reqs {
			inner, err := elements(rq.Bytes)
			if err != nil || len(inner) == 0 {
				return nil, malformed("Request", err)
			}
			var id CertID
			if err := unmarshal(inner[0].FullBytes, &id); err != nil {
				return nil, malformed("reqCert", err)
			}
			out = append(out, id)
		}
		return out, nil
	}
	return nil, malformed("no requestList", nil)
}

// --- writing responses (test responders) ---------------------------------------

func explicit(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

// CreateResponse writes a successful, signed basic OCSP response for the
// given single responses. certs are embedded, responder first, and the
// responder is named by key hash. key must be the responder's ECDSA key
// (signature ecdsa-with-SHA256).
func CreateResponse(certs []*x509.Certificate, key crypto.Signer, singles []Single, producedAt time.Time) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("ocsp: no responder certificate")
	}
	responder := certs[0]
	var responses []asn1.RawValue
	for _, s := range singles {
		id, err := asn1.Marshal(s.CertID)
		if err != nil {
			return nil, err
		}
		var status asn1.RawValue
		switch s.Status {
		case Good:
			status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}
		case Unknown:
			status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2}
		case Revoked:
			t, err := asn1.MarshalWithParams(s.RevokedAt.UTC(), "generalized")
			if err != nil {
				return nil, err
			}
			if s.Reason >= 0 {
				r, err := asn1.Marshal(asn1.Enumerated(s.Reason))
				if err != nil {
					return nil, err
				}
				rv, err := asn1.Marshal(explicit(0, r))
				if err != nil {
					return nil, err
				}
				t = append(t, rv...)
			}
			status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: t}
		}
		this, err := asn1.MarshalWithParams(s.ThisUpdate.UTC(), "generalized")
		if err != nil {
			return nil, err
		}
		body, err := asn1.Marshal(status)
		if err != nil {
			return nil, err
		}
		body = append(append(id, body...), this...)
		if !s.NextUpdate.IsZero() {
			next, err := asn1.MarshalWithParams(s.NextUpdate.UTC(), "generalized")
			if err != nil {
				return nil, err
			}
			nv, err := asn1.Marshal(explicit(0, next))
			if err != nil {
				return nil, err
			}
			body = append(body, nv...)
		}
		responses = append(responses, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	}
	_, keyHash, ok := issuerHashes(crypto.SHA1, responder)
	if !ok {
		return nil, malformed("responder key", nil)
	}
	kh, err := asn1.Marshal(keyHash)
	if err != nil {
		return nil, err
	}
	tbs, err := asn1.Marshal(struct {
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []asn1.RawValue
	}{explicit(2, kh), producedAt.UTC(), responses})
	if err != nil {
		return nil, err
	}
	digest := crypto.SHA256.New()
	digest.Write(tbs)
	sig, err := key.Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	certSeq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: raw})
	if err != nil {
		return nil, err
	}
	basic, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		SigAlg    pkix.AlgorithmIdentifier
		Signature asn1.BitString
		Certs     asn1.RawValue
	}{
		asn1.RawValue{FullBytes: tbs},
		pkix.AlgorithmIdentifier{Algorithm: sigAlgs[3].oid},
		asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
		explicit(0, certSeq),
	})
	if err != nil {
		return nil, err
	}
	rb, err := asn1.Marshal(struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}{oidBasic, basic})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Status asn1.Enumerated
		Bytes  asn1.RawValue
	}{0, explicit(0, rb)})
}

// MaxResponse bounds a fetched response, as c2pa-rs does (1 MB).
const MaxResponse = 1 << 20

// ErrFetch wraps every failure to fetch a response.
var ErrFetch = errors.New("ocsp: fetch")

// Fetch asks cert's OCSP responders (its AIA OCSP URLs, in order) about
// cert, the way c2pa-rs does: GET <url>/<base64 request>. It returns the
// first response with HTTP status 200, unverified.
func Fetch(client *http.Client, cert, issuer *x509.Certificate) ([]byte, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("%w: certificate has no OCSP URL", ErrFetch)
	}
	req, err := CreateRequest(cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	enc := url.PathEscape(base64.StdEncoding.EncodeToString(req))
	var last error
	for _, server := range cert.OCSPServer {
		u := server
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		resp, err := client.Get(u + enc)
		if err != nil {
			last = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("%s: HTTP %d", server, resp.StatusCode)
			continue
		}
		return b, nil
	}
	return nil, fmt.Errorf("%w: %w", ErrFetch, last)
}

// Find returns the single response for cert issued by issuer, or nil.
func (r *Response) Find(cert, issuer *x509.Certificate) *Single {
	for i := range r.Responses {
		if r.Responses[i].CertID.Matches(cert, issuer) {
			return &r.Responses[i]
		}
	}
	return nil
}
