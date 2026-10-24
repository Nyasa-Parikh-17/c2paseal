package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"time"
)

// Extension and EKU object identifiers.
var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

	oidEKUDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
	oidEKUMicrosoftC2PA   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 76, 59, 1, 9}
	oidEKUC2PASigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62558, 2, 1}
)

// handledCritical lists the extensions c2pa-rs understands; any other
// critical extension makes the certificate invalid.
var handledCritical = []asn1.ObjectIdentifier{
	{2, 5, 29, 35},                // authority key identifier
	{2, 5, 29, 14},                // subject key identifier
	{2, 5, 29, 15},                // key usage
	{2, 5, 29, 32},                // certificate policies
	{2, 5, 29, 33},                // policy mappings
	{2, 5, 29, 17},                // subject alternative name
	{2, 5, 29, 19},                // basic constraints
	{2, 5, 29, 30},                // name constraints
	{2, 5, 29, 36},                // policy constraints
	{2, 5, 29, 37},                // extended key usage
	{2, 5, 29, 31},                // CRL distribution points
	{2, 5, 29, 54},                // inhibit any-policy
	{1, 3, 6, 1, 5, 5, 7, 1, 1},   // authority information access
	{2, 16, 840, 1, 113730, 1, 1}, // Netscape cert type
	{2, 5, 29, 20},                // CRL number
	{2, 5, 29, 21},                // reason code
	{2, 5, 29, 24},                // invalidity date
}

var allowedSigAlgs = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
	x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
	x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
	x509.PureEd25519,
}

// EKUs accepted beyond emailProtection, timeStamping and OCSPSigning (which
// c2pa-rs always accepts): its valid_eku_oids.cfg list for claim signers,
// nothing extra for time-stamp authorities.
var (
	signerEKUs = []asn1.ObjectIdentifier{oidEKUDocumentSigning, oidEKUMicrosoftC2PA, oidEKUC2PASigning}
	tsaEKUs    []asn1.ObjectIdentifier
)

// checkProfile applies the C2PA certificate profile to an end-entity
// certificate at time t (a validated time-stamp's time, else now). It
// mirrors c2pa-rs check_end_entity_certificate_profile and returns the first
// problem as (code, explanation), or ("", "") if the certificate passes.
func checkProfile(cert *x509.Certificate, t time.Time, otherEKUs []asn1.ObjectIdentifier) (code, explanation string) {
	invalid := func(why string) (string, string) { return SigningCredentialInvalid, why }

	if cert.Version != 3 {
		return invalid("certificate version incorrect")
	}
	if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
		return SigningCredentialExpired, "certificate expired"
	}
	if !slices.Contains(allowedSigAlgs, cert.SignatureAlgorithm) {
		return invalid("certificate algorithm not supported")
	}
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if c := pub.Curve; c != elliptic.P256() && c != elliptic.P384() && c != elliptic.P521() {
			return invalid("certificate unsupported EC curve")
		}
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return invalid("certificate key length too short")
		}
	}
	isCA := cert.BasicConstraintsValid && cert.IsCA
	if isCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return invalid("certificate issuer and subject cannot be the same (self-signed disallowed)")
	}

	ekuGood := isCA // an end-entity certificate must have an EKU extension
	if hasExtension(cert, oidExtExtKeyUsage) {
		if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
			return invalid("certificate 'any' EKU not allowed")
		}
		if !hasAllowedEKU(cert, otherEKUs) {
			return invalid("certificate missing required EKU")
		}
		has := func(u x509.ExtKeyUsage) bool { return slices.Contains(cert.ExtKeyUsage, u) }
		ocsp, ts := has(x509.ExtKeyUsageOCSPSigning), has(x509.ExtKeyUsageTimeStamping)
		others := has(x509.ExtKeyUsageClientAuth) || has(x509.ExtKeyUsageCodeSigning) ||
			has(x509.ExtKeyUsageEmailProtection) || has(x509.ExtKeyUsageServerAuth) || hasOtherEKU(cert)
		if (ocsp && ts) || ((ocsp != ts) && others) {
			return invalid("certificate invalid set of EKUs")
		}
		ekuGood = true
	}

	kuGood := false
	if hasExtension(cert, oidExtKeyUsage) {
		ku := cert.KeyUsage
		if ku&x509.KeyUsageDigitalSignature != 0 {
			if ku&x509.KeyUsageCertSign != 0 && !isCA {
				return invalid("certificate missing digitalSignature EKU")
			}
			kuGood = true
		}
		if ku&(x509.KeyUsageCertSign|x509.KeyUsageContentCommitment) != 0 {
			kuGood = true
		}
	}
	akiGood := len(cert.AuthorityKeyId) > 0
	skiGood := !isCA || len(cert.SubjectKeyId) > 0
	criticalGood := true
	for _, e := range cert.Extensions {
		if e.Critical && !slices.ContainsFunc(handledCritical, e.Id.Equal) {
			criticalGood = false
		}
	}
	if !(akiGood && skiGood && kuGood && ekuGood && criticalGood) {
		return invalid("certificate params incorrect")
	}
	if isCA {
		return invalid("expected end-entity certificate")
	}
	return "", ""
}

func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(cert.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oid) })
}

// hasAllowedEKU reports whether the certificate carries an accepted EKU.
func hasAllowedEKU(cert *x509.Certificate, other []asn1.ObjectIdentifier) bool {
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageEmailProtection || u == x509.ExtKeyUsageTimeStamping || u == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if slices.ContainsFunc(other, oid.Equal) {
			return true
		}
	}
	return false
}

// hasOtherEKU reports EKUs outside the seven x509-parser names (any,
// serverAuth, clientAuth, codeSigning, emailProtection, timeStamping,
// OCSPSigning), which c2pa-rs counts as "other".
func hasOtherEKU(cert *x509.Certificate) bool {
	if len(cert.UnknownExtKeyUsage) > 0 {
		return true
	}
	for _, u := range cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning:
		default:
			return true
		}
	}
	return false
}
