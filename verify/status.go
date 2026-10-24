package verify

// Kind is the class of a status code, as reported by c2patool:
// validation_results groups codes into success, informational and failure.
type Kind int

const (
	Success Kind = iota
	Informational
	Failure
)

func (k Kind) String() string {
	switch k {
	case Success:
		return "success"
	case Informational:
		return "informational"
	}
	return "failure"
}

// Status codes in scope for C2paSeal (C2PA 2.4 §15, names as in c2pa-rs
// validation_results.rs).
const (
	// Success.
	ClaimSignatureValidated      = "claimSignature.validated"
	ClaimSignatureInsideValidity = "claimSignature.insideValidity"
	SigningCredentialTrusted     = "signingCredential.trusted"
	TimeStampValidated           = "timeStamp.validated"
	TimeStampTrusted             = "timeStamp.trusted"
	AssertionHashedURIMatch      = "assertion.hashedURI.match"
	AssertionDataHashMatch       = "assertion.dataHash.match"
	IngredientManifestValidated  = "ingredient.manifest.validated"

	// Informational.
	TimeStampUntrusted       = "timeStamp.untrusted"
	TimeStampOutsideValidity = "timeStamp.outsideValidity"
	TimeStampMismatch        = "timeStamp.mismatch"
	TimeStampMalformed       = "timeStamp.malformed"
	AlgorithmDeprecated      = "algorithm.deprecated"
	IngredientUnknownProv    = "ingredient.unknownProvenance"
	AssertionDataHashExtra   = "assertion.dataHash.additionalExclusionsPresent"

	// Failure.
	ClaimMalformed                    = "claim.malformed"
	ClaimMissing                      = "claim.missing"
	ClaimCBORInvalid                  = "claim.cbor.invalid"
	ClaimHardBindingsMissing          = "claim.hardBindings.missing"
	ClaimMultiple                     = "claim.multiple"
	ClaimSignatureMissing             = "claimSignature.missing"
	ClaimSignatureMismatch            = "claimSignature.mismatch"
	ClaimSignatureOutsideValid        = "claimSignature.outsideValidity"
	SigningCredentialUntrusted        = "signingCredential.untrusted"
	SigningCredentialInvalid          = "signingCredential.invalid"
	SigningCredentialExpired          = "signingCredential.expired"
	AssertionHashedURIMismatch        = "assertion.hashedURI.mismatch"
	AssertionMissing                  = "assertion.missing"
	AssertionUndeclared               = "assertion.undeclared"
	AssertionOutsideManifest          = "assertion.outsideManifest"
	AssertionIngredientMalformed      = "assertion.ingredient.malformed"
	AssertionActionIngredientMismatch = "assertion.action.ingredientMismatch"
	IngredientManifestMismatch        = "ingredient.manifest.mismatch"
	IngredientManifestMissing         = "ingredient.manifest.missing"
	AssertionMultipleHardBinding      = "assertion.multipleHardBindings"
	AssertionCBORInvalid              = "assertion.cbor.invalid"
	AssertionJSONInvalid              = "assertion.json.invalid"
	AssertionActionMalformed          = "assertion.action.malformed"
	AssertionDataHashMismatch         = "assertion.dataHash.mismatch"
	AssertionDataHashMalformed        = "assertion.dataHash.malformed"
	AlgorithmUnsupported              = "algorithm.unsupported"
	ManifestMissing                   = "manifest.missing"
	GeneralError                      = "general.error"
)

// KindOf classifies a status code the way c2pa-rs log_kind does: a fixed
// set of success and informational codes; everything else is a failure.
// (log_kind also lists ingredient.manifest.missing as success, but c2pa-rs
// logs and reports it as a failure, so it is a failure here.)
func KindOf(code string) Kind {
	switch code {
	case ClaimSignatureValidated, ClaimSignatureInsideValidity, SigningCredentialTrusted,
		TimeStampValidated, TimeStampTrusted, AssertionHashedURIMatch, AssertionDataHashMatch,
		"signingCredential.ocsp.notRevoked", "assertion.bmffHash.match", "assertion.accessible",
		"assertion.boxesHash.match", "assertion.collectionHash.match",
		IngredientManifestValidated, "ingredient.claimSignature.validated":
		return Success
	case TimeStampUntrusted, TimeStampOutsideValidity, TimeStampMismatch, TimeStampMalformed,
		AlgorithmDeprecated, "signingCredential.ocsp.skipped", "signingCredential.ocsp.inaccessible",
		"manifest.unknownProvenance", "timeOfSigning.insideValidity",
		IngredientUnknownProv, AssertionDataHashExtra:
		return Informational
	}
	return Failure
}

// Status is one validation result.
type Status struct {
	Code        string `json:"code"`
	URL         string `json:"url,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}

// Kind returns the status code's class.
func (s Status) Kind() Kind { return KindOf(s.Code) }
