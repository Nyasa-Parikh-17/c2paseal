package verify

import (
	"crypto/x509"
	"slices"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// timeStamp validates the RFC 3161 time-stamp in a claim signature, the way
// c2pa-rs does (crypto/cose/sigtst.rs, crypto/time_stamp/verify.rs). It
// returns the statuses to log and, only if the time-stamp is valid *and*
// its authority is trusted, the time to use for certificate checks.
//
// For v1 claims c2pa-rs does not check the authority's trust
// (claim.rs verify_claim), so a valid v1 time-stamp is reported trusted.
//
// Every time-stamp status is success or informational: a bad time-stamp
// never makes a manifest invalid by itself.
func timeStamp(m *manifest.Manifest, opts *Options) ([]Status, *time.Time) {
	out, trustedAt, _ := checkStamp(m, opts, m.Claim.Version != 1)
	return out, trustedAt
}

// SigningTime returns the time a manifest's time-stamp asserts, if the
// token is valid for the signature, whatever its authority's trust. This is
// what c2patool reports as signature.time (c2pa-rs signing_time_from_sign1):
// the CMS signingTime attribute if present, else the TSTInfo genTime.
func SigningTime(m *manifest.Manifest) (time.Time, bool) {
	_, _, at := checkStamp(m, nil, false)
	if at == nil {
		return time.Time{}, false
	}
	return *at, true
}

// checkStamp is timeStamp with the authority trust check optional. It also
// returns the asserted time of a token that is valid apart from trust.
func checkStamp(m *manifest.Manifest, opts *Options, checkTrust bool) (out []Status, trustedAt, validAt *time.Time) {
	s := m.Signature
	if s == nil || len(s.Timestamps) == 0 {
		return nil, nil, nil
	}
	url := SignatureURL(m)
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
		return out, nil, nil
	}

	// sigTst2 time-stamps the signature (as a CBOR byte string); sigTst the
	// claim. Either way the token's imprint covers a COSE CounterSignature
	// structure over that data.
	data := m.Claim.Raw
	if version == 2 {
		b, err := cbormode.Enc.Marshal(s.Signature)
		if err != nil {
			return out, nil, nil
		}
		data = b
	}
	tbs, err := cbormode.Enc.Marshal([]any{"CounterSignature", s.Protected, []byte{}, data})
	if err != nil {
		return out, nil, nil
	}

	tok, err := parseToken(tokens[0])
	if err != nil {
		add(TimeStampMalformed, "could not parse timestamp data")
		return out, nil, nil
	}
	if !tok.hasCerts || !tok.certsOK {
		add(TimeStampUntrusted, "could not parse timestamp data")
		return out, nil, nil
	}

	// Any signer that validates will do; otherwise the last one tried is
	// reported.
	var last []tsStatus
	for _, sg := range tok.signers {
		cert := tok.cert(sg)
		if cert == nil {
			last = nil
			continue
		}
		cur, at, ok := tok.checkSigner(sg, cert, tbs)
		if ok {
			if validAt == nil {
				validAt = &at
			}
			trustOK := true
			if checkTrust {
				cur, trustOK = tsaTrust(cur, cert, tok.certs, at, opts)
			}
			if trustOK {
				cur = append(cur, tsStatus{TimeStampTrusted, "timestamp cert trusted: " + cert.Subject.CommonName})
				for _, st := range cur {
					add(st.code, st.why)
				}
				return out, &at, &at
			}
		}
		last = cur
	}
	for _, st := range last {
		add(st.code, st.why)
	}
	return out, nil, validAt
}

// tsaTrust checks that the time-stamp authority is a valid end entity with
// the timeStamping EKU that chains to a trust anchor at time at.
func tsaTrust(cur []tsStatus, cert *x509.Certificate, certs []*x509.Certificate, at time.Time, opts *Options) ([]tsStatus, bool) {
	untrusted := tsStatus{TimeStampUntrusted, "timestamp cert untrusted: " + cert.Subject.CommonName}
	if code, why := checkProfile(cert, at, tsaEKUs); code != "" {
		return append(cur, tsStatus{code, why}, untrusted), false
	}
	others := slices.DeleteFunc(slices.Clone(certs), func(c *x509.Certificate) bool { return c == cert })
	if !trusted(cert, others, &at, opts) {
		return append(cur, untrusted), false
	}
	return cur, true
}
