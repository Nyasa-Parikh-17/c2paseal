package verify

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/bmff"
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
		out = append(out, Status{Code: ClaimHardBindingsMissing, URL: claimURL, Explanation: "claim missing data binding"})
	}
	if len(bindings) > 1 {
		out = append(out, Status{Code: AssertionMultipleHardBinding, URL: claimURL, Explanation: "claim has multiple data bindings"})
	}

	for _, a := range bindings {
		url := assertionURL(m.Label, a.Label)
		if base := assertion.BaseLabel(a.Label); assertion.IsBMFFHash(base) {
			out = append(out, bmffBinding(m, a, url, assertion.BMFFHashVersion(base), file))
			continue
		}
		if assertion.BaseLabel(a.Label) != assertion.LabelDataHash {
			// Boxes and collection hashes are out of scope.
			out = append(out, Status{Code: GeneralError, URL: url, Explanation: "unsupported hard binding: " + a.Label})
			continue
		}
		dh, ok := a.Value.(*assertion.DataHash)
		if !ok {
			out = append(out, Status{Code: AssertionDataHashMalformed, URL: url, Explanation: "data hash could not be parsed"})
			continue
		}
		if len(dh.Exclusions) > 1 {
			out = append(out, Status{Code: AssertionDataHashExtra, URL: url, Explanation: "extra data hash exclusions found"})
		}
		if dh.URL != "" {
			out = append(out, Status{Code: AssertionDataHashMismatch, URL: a.Label, Explanation: "remote data hash URIs are not supported"})
			continue
		}
		name := cmp.Or(dh.Name, "unnamed")
		alg := cmp.Or(dh.Alg, m.Claim.Alg, manifest.DefaultAlg)
		if err := checkDataHash(file, alg, dh); err != nil {
			out = append(out, Status{Code: AssertionDataHashMismatch, URL: url, Explanation: fmt.Sprintf("asset hash error, name: %s, error: hash verification( %s )", name, err)})
			continue
		}
		out = append(out, Status{Code: AssertionDataHashMatch, URL: url, Explanation: "data hash valid"})
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

// bmffBinding checks a c2pa.hash.bmff assertion against the file
// (c2pa-rs BmffHash::verify_stream_hash for a flat, non-fragmented file).
// Versions 2 and 3 hash each top-level box's offset as well.
func bmffBinding(m *manifest.Manifest, a assertion.Assertion, url string, version int, file []byte) Status {
	bh, ok := a.Value.(*assertion.BMFFHash)
	if !ok || !bmffWellFormed(bh) {
		return Status{Code: AssertionBMFFHashMalformed, URL: url, Explanation: "BMFF hash could not be parsed"}
	}
	name := cmp.Or(bh.Name, "unnamed")
	fail := func(why string) Status {
		return Status{Code: AssertionBMFFHashMismatch, URL: url, Explanation: fmt.Sprintf("asset hash error, name: %s, error: %s", name, why)}
	}
	switch {
	case bh.URL != "":
		return fail("BMFF hash remote has been deprecated")
	case len(bh.Merkle) > 0:
		return Status{Code: GeneralError, URL: url, Explanation: "BMFF Merkle hashes (fragmented files) are not supported"}
	case bh.Hash == nil:
		return fail("no file hash")
	}
	h, err := manifest.NewHash(cmp.Or(bh.Alg, m.Claim.Alg, manifest.DefaultAlg))
	if err != nil {
		return fail(err.Error())
	}
	got, err := bmff.Digest(h, file, bmffExclusions(bh.Exclusions), version > 1)
	if err != nil {
		return fail(err.Error())
	}
	if !bytes.Equal(got, bh.Hash) {
		return fail(AssertionBMFFHashMismatch)
	}
	return Status{Code: AssertionBMFFHashMatch, URL: url, Explanation: "BMFF hash valid"}
}

// bmffWellFormed is c2pa-rs's verify_self: there are exclusions, and every
// exclusion's subsets are sorted by offset and do not overlap.
func bmffWellFormed(bh *assertion.BMFFHash) bool {
	if len(bh.Exclusions) == 0 {
		return false
	}
	for _, e := range bh.Exclusions {
		for i := 1; i < len(e.Subset); i++ {
			prev := e.Subset[i-1]
			end := prev.Offset + prev.Length
			if e.Subset[i].Offset < prev.Offset || end < prev.Offset || end > e.Subset[i].Offset {
				return false
			}
		}
	}
	return true
}

func bmffExclusions(in []assertion.BMFFExclusion) []bmff.Exclusion {
	out := make([]bmff.Exclusion, 0, len(in))
	for _, e := range in {
		x := bmff.Exclusion{XPath: e.XPath, Length: e.Length, Version: e.Version, Flags: e.Flags, Exact: e.Exact}
		for _, d := range e.Data {
			x.Data = append(x.Data, bmff.DataMatch{Offset: d.Offset, Value: d.Value})
		}
		if e.Subset != nil {
			x.Subset = []bmff.Subset{}
			for _, s := range e.Subset {
				x.Subset = append(x.Subset, bmff.Subset{Offset: s.Offset, Length: s.Length})
			}
		}
		out = append(out, x)
	}
	return out
}
