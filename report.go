package c2paseal

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	"github.com/digitorus/timestamp"
)

// The JSON report mirrors `c2patool <file> --detailed` (c2pa-rs
// manifest_store_report.rs) for the fields this library reads.

type storeReport struct {
	ActiveManifest string                    `json:"active_manifest"`
	Manifests      map[string]manifestReport `json:"manifests"`
}

type manifestReport struct {
	Claim          map[string]any  `json:"claim"`
	AssertionStore map[string]any  `json:"assertion_store"`
	Signature      signatureReport `json:"signature"`
}

type signatureReport struct {
	Alg        string  `json:"alg"`
	Issuer     *string `json:"issuer,omitempty"`
	CommonName *string `json:"common_name,omitempty"`
	Time       *string `json:"time,omitempty"`
}

// MarshalJSON renders the store like c2patool --detailed, without the
// validation results.
func (s *ManifestStore) MarshalJSON() ([]byte, error) {
	r := storeReport{ActiveManifest: s.Active.Label, Manifests: map[string]manifestReport{}}
	for _, m := range s.Manifests {
		mr, err := reportManifest(m)
		if err != nil {
			return nil, fmt.Errorf("c2paseal: manifest %q: %w", m.Label, err)
		}
		r.Manifests[m.Label] = mr
	}
	return json.Marshal(r)
}

func reportManifest(m *manifest.Manifest) (manifestReport, error) {
	var claim map[string]any
	if err := cbormode.Dec.Unmarshal(m.Claim.Raw, &claim); err != nil {
		return manifestReport{}, err
	}
	claim["claim_version"] = 2

	store := map[string]any{}
	for _, a := range m.Assertions {
		v, err := assertionValue(a.Box)
		if err != nil {
			return manifestReport{}, fmt.Errorf("assertion %q: %w", a.Label, err)
		}
		store[a.Label] = v
	}
	return manifestReport{Claim: claim, AssertionStore: store, Signature: reportSignature(m.Signature)}, nil
}

// assertionValue renders an assertion's content the way c2pa-rs does: CBOR
// and JSON as JSON values, embedded files as "<omitted> len = N".
func assertionValue(box *jumbf.Box) (any, error) {
	c := box.Contents()
	if len(c) == 0 {
		return nil, nil
	}
	switch c[0].Type {
	case "cbor":
		var v any
		err := cbormode.Dec.Unmarshal(c[0].Payload, &v)
		return v, err
	case "json":
		return json.RawMessage(c[0].Payload), nil
	case "bfdb":
		if len(c) == 2 && c[1].Type == "bidb" {
			return fmt.Sprintf("<omitted> len = %d", len(c[1].Payload)), nil
		}
	}
	return nil, nil
}

func reportSignature(s *cose.Sign1) signatureReport {
	if s == nil {
		return signatureReport{}
	}
	r := signatureReport{Alg: cose.AlgName(s.Alg)}
	if cert, err := x509.ParseCertificate(s.X5Chain[0]); err == nil {
		if o := cert.Subject.Organization; len(o) > 0 {
			r.Issuer = &o[len(o)-1]
		}
		if cn := cert.Subject.CommonName; cn != "" {
			r.CommonName = &cn
		}
	}
	for _, ts := range s.Timestamps {
		if t, err := timestamp.Parse(ts.Token); err == nil {
			str := rfc3339(t.Time)
			r.Time = &str
			break
		}
	}
	return r
}

// rfc3339 formats t like chrono's DateTime::to_rfc3339: "+00:00" for UTC and
// fractional seconds in groups of 3, 6 or 9 digits only when non-zero.
func rfc3339(t time.Time) string {
	t = t.UTC()
	frac := ""
	switch ns := t.Nanosecond(); {
	case ns == 0:
	case ns%1_000_000 == 0:
		frac = fmt.Sprintf(".%03d", ns/1_000_000)
	case ns%1_000 == 0:
		frac = fmt.Sprintf(".%06d", ns/1_000)
	default:
		frac = fmt.Sprintf(".%09d", ns)
	}
	return t.Format("2006-01-02T15:04:05") + frac + "+00:00"
}
