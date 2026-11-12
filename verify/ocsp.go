package verify

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net/http"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/ocsp"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// OCSP status codes (C2PA 2.4 §15.10.2).
const (
	SigningCredentialNotRevoked       = "signingCredential.ocsp.notRevoked"
	SigningCredentialRevoked          = "signingCredential.ocsp.revoked"
	SigningCredentialOCSPUnknown      = "signingCredential.ocsp.unknown"
	SigningCredentialOCSPInaccessible = "signingCredential.ocsp.inaccessible"
)

// defaultFetchTimeout bounds an OCSP fetch without Options.HTTPClient.
const defaultFetchTimeout = 30 * time.Second

// ocspResponseURL is the URL c2pa-rs logs OCSP response statuses under.
const ocspResponseURL = "OCSP_RESPONSE"

// ocspEKUs: an OCSP responder needs id-kp-OCSPSigning, which checkProfile
// always accepts; nothing extra.
var ocspEKUs []asn1.ObjectIdentifier

// checkOCSP checks the signer certificate's revocation status the way
// c2pa-rs check_ocsp_status does, before the signature itself is checked.
// signingTime is a valid, trusted time-stamp's time, or nil.
//
// A stapled response (rVals) is used only if its responder certificate is
// a valid OCSP signer that is trusted; then good gives an informational
// signingCredential.ocsp.notRevoked and revoked an informational
// signingCredential.ocsp.revoked, which ends the claim's validation (stop
// is true). Without a stapled response, and only with Options.FetchOCSP,
// the responder named in the certificate is asked; its answer is logged as
// success or failure, and an unreachable responder as informational
// signingCredential.ocsp.inaccessible.
func checkOCSP(m *manifest.Manifest, signingTime *time.Time, opts *Options) (out []Status, stop bool) {
	s := m.Signature
	if s == nil {
		return nil, false
	}
	chain, err := parseChain(s.X5Chain)
	if err != nil {
		return nil, false
	}
	url := SignatureURL(m)

	if len(s.OCSP) > 0 {
		statuses, ok := stapledOCSP(s.OCSP[0], chain, signingTime, opts)
		if !ok {
			return nil, false
		}
		serial := chain[0].SerialNumber.String()
		for _, st := range statuses {
			switch st.Code {
			case SigningCredentialRevoked:
				return []Status{(Status{Code: SigningCredentialRevoked, URL: url, Explanation: "signing cert revoked: " + serial}).withKind(Informational)}, true
			}
		}
		for _, st := range statuses {
			if st.Code == SigningCredentialNotRevoked {
				return []Status{(Status{Code: SigningCredentialNotRevoked, URL: url, Explanation: "signing cert not revoked: " + serial}).withKind(Informational)}, false
			}
		}
		return nil, false
	}

	if opts == nil || !opts.FetchOCSP || len(chain) < 2 {
		return nil, false
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}
	der, err := ocsp.Fetch(client, chain[0], chain[1])
	if err != nil {
		return []Status{{Code: SigningCredentialOCSPInaccessible, URL: url, Explanation: "signing cert not fetched"}}, false
	}
	r, statuses := readOCSP(der, chain, signingTime, opts.now())
	if r == nil || len(r.Certs) == 0 {
		return nil, false
	}
	if code, _ := checkProfile(r.Certs[0], responderTime(signingTime, opts), ocspEKUs); code != "" {
		return nil, false
	}
	return statuses, false
}

// stapledOCSP reads a stapled response and checks its responder: a valid
// OCSP signer (profile) that is trusted at the signing time. ok is false if
// the response must be ignored.
func stapledOCSP(der []byte, chain []*x509.Certificate, signingTime *time.Time, opts *Options) ([]Status, bool) {
	r, statuses := readOCSP(der, chain, signingTime, opts.now())
	if r == nil || len(r.Certs) == 0 {
		return nil, false
	}
	responder := r.Certs[0]
	if code, _ := checkProfile(responder, responderTime(signingTime, opts), ocspEKUs); code != "" {
		return nil, false
	}
	if !trusted(responder, r.Certs, signingTime, opts) {
		return nil, false
	}
	return statuses, true
}

func responderTime(signingTime *time.Time, opts *Options) time.Time {
	if signingTime != nil {
		return *signingTime
	}
	return opts.now()
}

// readOCSP is c2pa-rs OcspResponse::from_der_checked: it returns the
// response (nil if it must be ignored: unreadable, unsuccessful, without a
// responder certificate, or with a signature that does not verify) and the
// statuses for the single responses about the signer.
func readOCSP(der []byte, chain []*x509.Certificate, signingTime *time.Time, now time.Time) (*ocsp.Response, []Status) {
	r, err := ocsp.ParseResponse(der)
	if err != nil || r.Status != 0 || len(r.Certs) == 0 || r.CheckSignature() != nil {
		return nil, nil
	}
	if len(chain) < 2 {
		return r, nil
	}
	revoked := func(why string) Status {
		return Status{Code: SigningCredentialRevoked, URL: ocspResponseURL, Explanation: why}
	}
	var out []Status
	for _, sr := range r.Responses {
		if !sr.CertID.Matches(chain[0], chain[1]) {
			continue
		}
		switch sr.Status {
		case ocsp.Good:
			next := sr.NextUpdate
			if next.IsZero() {
				next = r.ProducedAt.Add(24 * time.Hour)
			}
			var inRange bool
			if signingTime != nil {
				st := *signingTime
				inRange = st.Before(sr.ThisUpdate) || !st.After(next)
			} else {
				inRange = !now.Before(sr.ThisUpdate)
			}
			if inRange {
				return r, append(out, Status{Code: SigningCredentialNotRevoked, URL: ocspResponseURL, Explanation: "certificate not revoked"})
			}
			out = append(out, revoked("certificate revoked"))
		case ocsp.Revoked:
			at := sr.RevokedAt.UTC()
			msg := fmt.Sprintf("certificate revoked at: %s", at.Format("2006-01-02 15:04:05 UTC"))
			switch {
			case sr.Reason < 0:
				out = append(out, revoked("certificate revoked"))
			case sr.Reason == ocsp.ReasonRemoveFromCRL:
				ref := now
				if signingTime != nil {
					ref = *signingTime
				}
				if !at.After(ref) {
					out = append(out, revoked(msg))
				}
			default:
				// Revoked after signing (by a trusted time) does not count.
				if signingTime != nil && signingTime.Before(at) {
					return r, out
				}
				out = append(out, revoked(msg))
			}
		case ocsp.Unknown:
			out = append(out, Status{Code: SigningCredentialOCSPUnknown, URL: ocspResponseURL, Explanation: "unknown certStatus"})
		}
	}
	return r, out
}

// parseChain parses x5chain, signer first.
func parseChain(ders [][]byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
