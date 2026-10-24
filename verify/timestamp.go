package verify

import (
	"bytes"
	"crypto/x509"
	"slices"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/digitorus/timestamp"
)

// timeStamp validates the RFC 3161 time-stamp in a claim signature, the way
// c2pa-rs does (crypto/cose/sigtst.rs, crypto/time_stamp/verify.rs). It
// returns the statuses to log and, only if the time-stamp is valid *and*
// its authority is trusted, the time to use for certificate checks.
//
// Every time-stamp status is success or informational: a bad time-stamp
// never makes a manifest invalid by itself.
func timeStamp(m *manifest.Manifest, opts *Options) ([]Status, *time.Time) {
	s := m.Signature
	if s == nil || len(s.Timestamps) == 0 {
		return nil, nil
	}
	url := SignatureURL(m)
	var out []Status
	add := func(code, why string) { out = append(out, Status{code, url, why}) }

	// Only the first time-stamp header is used: sigTst2 if present, else sigTst.
	version := s.Timestamps[0].Version
	var tokens [][]byte
	for _, t := range s.Timestamps {
		if t.Version == version {
			tokens = append(tokens, t.Token)
		}
	}
	if len(tokens) > 1 {
		add(TimeStampMalformed, "only a single timestamp response is allowed in a manifest")
		return out, nil
	}

	// sigTst2 time-stamps the signature (as a CBOR byte string); sigTst the
	// claim. Either way the token's imprint covers a COSE CounterSignature
	// structure over that data.
	data := m.Claim.Raw
	if version == 2 {
		b, err := cbormode.Enc.Marshal(s.Signature)
		if err != nil {
			return out, nil
		}
		data = b
	}
	tbs, err := cbormode.Enc.Marshal([]any{"CounterSignature", s.Protected, []byte{}, data})
	if err != nil {
		return out, nil
	}

	// Parse checks the token's CMS signature with its embedded certificates.
	ts, err := timestamp.Parse(tokens[0])
	if err != nil {
		add(TimeStampMalformed, "could not parse timestamp data")
		return out, nil
	}
	signer := tsaSigner(ts.Certificates)
	if signer == nil {
		add(TimeStampUntrusted, "could not parse timestamp data")
		return out, nil
	}
	cn := signer.Subject.CommonName
	at := ts.Time
	if at.Before(signer.NotBefore) || at.After(signer.NotAfter) {
		add(TimeStampOutsideValidity, "timestamp signer outside of certificate validity")
		return out, nil
	}
	if !ts.HashAlgorithm.Available() {
		add(TimeStampUntrusted, "timestamp unknown message digest algorithm")
		return out, nil
	}
	h := ts.HashAlgorithm.New()
	h.Write(tbs)
	if !bytes.Equal(h.Sum(nil), ts.HashedMessage) {
		add(TimeStampMismatch, "timestamp message digest did not match: "+cn)
		return out, nil
	}
	add(TimeStampValidated, "timestamp message digest matched: "+cn)

	// The authority must be a valid end entity and chain to a trust anchor.
	if code, why := checkProfile(signer, at, tsaEKUs); code != "" {
		add(code, why)
		add(TimeStampUntrusted, "timestamp cert untrusted: "+cn)
		return out, nil
	}
	others := slices.DeleteFunc(slices.Clone(ts.Certificates), func(c *x509.Certificate) bool { return c == signer })
	if !trusted(signer, others, &at, opts) {
		add(TimeStampUntrusted, "timestamp cert untrusted: "+cn)
		return out, nil
	}
	add(TimeStampTrusted, "timestamp cert trusted: "+cn)
	return out, &at
}

// tsaSigner picks the time-stamping certificate from a token's embedded
// certificates: the first non-CA certificate with the timeStamping EKU,
// else the first non-CA certificate.
func tsaSigner(certs []*x509.Certificate) *x509.Certificate {
	var fallback *x509.Certificate
	for _, c := range certs {
		if c.IsCA {
			continue
		}
		if slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
			return c
		}
		if fallback == nil {
			fallback = c
		}
	}
	return fallback
}
