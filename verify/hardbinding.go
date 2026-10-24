package verify

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
)

// hardBinding checks the active manifest's c2pa.hash.data assertion against
// the file (c2pa-rs claim.rs verify_hash_binding).
func hardBinding(m *manifest.Manifest, file []byte) []Status {
	var bindings []assertion.Assertion
	for _, a := range m.Assertions {
		if strings.HasPrefix(assertion.BaseLabel(a.Label), "c2pa.hash.") {
			bindings = append(bindings, a)
		}
	}
	var out []Status
	claimURL := ManifestURL(m.Label)
	if len(bindings) == 0 {
		out = append(out, Status{ClaimHardBindingsMissing, claimURL, "claim missing data binding"})
	}
	if len(bindings) > 1 {
		out = append(out, Status{AssertionMultipleHardBinding, claimURL, "claim has multiple data bindings"})
	}

	for _, a := range bindings {
		url := assertionURL(m.Label, a.Label)
		if assertion.BaseLabel(a.Label) != assertion.LabelDataHash {
			// BMFF, boxes and collection hashes are out of scope.
			out = append(out, Status{GeneralError, url, "unsupported hard binding: " + a.Label})
			continue
		}
		dh, ok := a.Value.(*assertion.DataHash)
		if !ok {
			out = append(out, Status{AssertionDataHashMalformed, url, "data hash could not be parsed"})
			continue
		}
		if len(dh.Exclusions) > 1 {
			out = append(out, Status{AssertionDataHashExtra, url, "extra data hash exclusions found"})
		}
		if dh.URL != "" {
			out = append(out, Status{AssertionDataHashMismatch, a.Label, "remote data hash URIs are not supported"})
			continue
		}
		name := cmp.Or(dh.Name, "unnamed")
		alg := cmp.Or(dh.Alg, m.Claim.Alg, manifest.DefaultAlg)
		if err := checkDataHash(file, alg, dh); err != nil {
			out = append(out, Status{AssertionDataHashMismatch, url,
				fmt.Sprintf("asset hash error, name: %s, error: hash verification( %s )", name, err)})
			continue
		}
		out = append(out, Status{AssertionDataHashMatch, url, "data hash valid"})
	}
	return out
}

// errHashMismatch matches c2pa-rs's wording in the mismatch explanation.
//
//lint:ignore ST1005 capitalised to reproduce c2patool's explanation text
var errHashMismatch = errors.New("Hashes do not match")

// checkDataHash hashes file with the exclusion ranges left out and compares
// the result with the assertion's hash.
func checkDataHash(file []byte, alg string, dh *assertion.DataHash) error {
	h, err := manifest.NewHash(alg)
	if err != nil {
		return err
	}
	ex := slices.Clone(dh.Exclusions)
	slices.SortFunc(ex, func(a, b assertion.Exclusion) int { return cmp.Compare(a.Start, b.Start) })
	pos := uint64(0)
	size := uint64(len(file))
	for _, e := range ex {
		if e.Start < pos {
			return errors.New("exclusions overlap")
		}
		if e.Start > size || e.Length > size-e.Start {
			return errors.New("exclusion outside the file")
		}
		h.Write(file[pos:e.Start])
		pos = e.Start + e.Length
	}
	h.Write(file[pos:])
	if !bytes.Equal(h.Sum(nil), dh.Hash) {
		return errHashMismatch
	}
	return nil
}
