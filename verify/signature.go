package verify

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	gocose "github.com/veraison/go-cose"
)

// Options configures verification.
type Options struct {
	// TrustAnchors are the root (or intermediate) certificates a signing
	// chain must lead to. Without any, every signer is untrusted; a valid
	// but untrusted chain gives signingCredential.untrusted, not a total
	// failure. Time-stamp authorities are checked against the same anchors.
	TrustAnchors []*x509.Certificate

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

func (o *Options) now() time.Time {
	if o == nil || o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// manifestLabel matches a v2 manifest label: urn:c2pa:<uuid> with optional
// :<claim generator> and :<version>_<reason> parts.
var manifestLabel = regexp.MustCompile(`^urn:c2pa:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(:[^:]*(:[^:]*)?)?$`)

// Signature checks a manifest's claim signature and signing credential,
// given the time from an already validated time-stamp (or nil). It is
// refChecks followed by credentials; Verify puts the time-stamp checks
// between the two, as c2pa-rs does.
func Signature(m *manifest.Manifest, signingTime *time.Time, opts *Options) []Status {
	return append(refChecks(m), credentials(m, signingTime, opts)...)
}

// refChecks reports a signature reference that does not name this
// manifest's signature box, and a malformed manifest label (c2pa-rs
// claim.rs verify_claim).
func refChecks(m *manifest.Manifest) []Status {
	var out []Status
	if !signatureRefOK(m) {
		out = append(out, Status{ClaimSignatureMissing, SignatureURL(m), "signature missing"})
	}
	if !manifestLabel.MatchString(m.Label) {
		out = append(out, Status{ClaimMalformed, ManifestURL(m.Label), "claim box label invalid"})
	}
	return out
}

// credentials checks the algorithm, signature encoding, certificate
// profile, trust, and finally the signature itself, in c2pa-rs order
// (crypto/cose/verifier.rs). Profile and trust problems do not stop the
// signature check.
func credentials(m *manifest.Manifest, signingTime *time.Time, opts *Options) []Status {
	url := SignatureURL(m)
	var out []Status
	add := func(code, why string) { out = append(out, Status{code, url, why}) }
	mismatch := func() []Status {
		add(ClaimSignatureMismatch, "claim signature is not valid")
		return out
	}

	s := m.Signature
	if s == nil {
		return mismatch()
	}
	if s.Alg != cose.AlgES256 {
		add(AlgorithmUnsupported, "unsupported or missing Cose algorithm")
		return mismatch()
	}
	if isDERSignature(s.Signature) {
		add(SigningCredentialInvalid, "unsupported signature format (EC signature should be in P1363 r|s format)")
		return mismatch()
	}
	leaf, err := x509.ParseCertificate(s.X5Chain[0])
	if err != nil {
		add(SigningCredentialInvalid, "certificate could not be parsed")
		return mismatch()
	}
	var chain []*x509.Certificate
	for _, der := range s.X5Chain[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			add(SigningCredentialInvalid, "certificate could not be parsed")
			return mismatch()
		}
		chain = append(chain, c)
	}

	at := opts.now()
	if signingTime != nil {
		at = *signingTime
	}
	if code, why := checkProfile(leaf, at, signerEKUs); code != "" {
		add(code, why)
	}
	if trusted(leaf, chain, signingTime, opts) {
		add(SigningCredentialTrusted, "signing certificate trusted, found in System trust anchors")
	} else {
		add(SigningCredentialUntrusted, "signing certificate untrusted")
	}

	if !validSignature(s, m.Claim.Raw, leaf) {
		return mismatch()
	}
	add(ClaimSignatureInsideValidity, "claim signature valid")
	add(ClaimSignatureValidated, "claim signature valid")
	return out
}

// signatureRefOK reports whether the claim's signature URI names this
// manifest's c2pa.signature box (c2pa-rs verify_claim).
func signatureRefOK(m *manifest.Manifest) bool {
	path, ok := strings.CutPrefix(m.Claim.Signature, manifest.JUMBFURIPrefix)
	if !ok {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if strings.HasPrefix(path, "/") && (len(parts) < 2 || parts[0] != manifest.LabelStore || parts[1] != m.Label) {
		return false
	}
	return parts[len(parts)-1] == manifest.LabelSignature
}

// isDERSignature reports whether an EC signature is ASN.1 DER instead of the
// raw r|s (IEEE P1363) form COSE requires.
func isDERSignature(sig []byte) bool {
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &v)
	return err == nil && len(rest) == 0
}

// trusted builds a chain from leaf through the given intermediates to a
// trust anchor. With a time-stamp, every certificate must be valid at that
// time. Without one, c2pa-rs uses OpenSSL's NO_CHECK_TIME; Go always checks
// validity, so the chain is tried at each certificate's notBefore and
// notAfter and accepted if it verifies at any of them.
func trusted(leaf *x509.Certificate, chain []*x509.Certificate, signingTime *time.Time, opts *Options) bool {
	if opts == nil || len(opts.TrustAnchors) == 0 {
		return false
	}
	roots := x509.NewCertPool()
	for _, a := range opts.TrustAnchors {
		roots.AddCert(a)
	}
	inter := x509.NewCertPool()
	for _, c := range chain {
		inter.AddCert(c)
	}
	var times []time.Time
	if signingTime != nil {
		times = []time.Time{*signingTime}
	} else {
		for _, c := range append(append([]*x509.Certificate{leaf}, chain...), opts.TrustAnchors...) {
			times = append(times, c.NotBefore, c.NotAfter)
		}
	}
	for _, at := range times {
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inter,
			CurrentTime:   at,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err == nil {
			return true
		}
	}
	return false
}

// validSignature rebuilds the COSE Sig_structure over the original claim
// bytes and verifies the ES256 signature with the signer's key.
func validSignature(s *cose.Sign1, claim []byte, leaf *x509.Certificate) bool {
	tbs, err := cbormode.Enc.Marshal([]any{"Signature1", s.Protected, []byte{}, claim})
	if err != nil {
		return false
	}
	v, err := gocose.NewVerifier(gocose.AlgorithmES256, leaf.PublicKey)
	if err != nil {
		return false
	}
	return v.Verify(tbs, s.Signature) == nil
}
