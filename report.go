package c2paseal

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// The JSON report mirrors `c2patool <file> --detailed` (c2pa-rs
// manifest_store_report.rs) for the fields this library reads.

type storeReport struct {
	ActiveManifest string                    `json:"active_manifest"`
	Manifests      map[string]manifestReport `json:"manifests"`
}

type manifestReport struct {
	Claim           map[string]any  `json:"claim"`
	AssertionStore  map[string]any  `json:"assertion_store"`
	CredentialStore []any           `json:"credential_store,omitempty"` // 1.x verifiable credentials
	Signature       signatureReport `json:"signature"`
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
	claim["claim_version"] = m.Claim.Version
	if m.Claim.Version == 1 && claim["claim_generator_info"] == nil {
		claim["claim_generator_info"] = []any{} // c2pa-rs prints an absent list as []
	}

	store := map[string]any{}
	for _, a := range m.Assertions {
		v, err := assertionValue(a.Box)
		if err != nil {
			return manifestReport{}, fmt.Errorf("assertion %q: %w", a.Label, err)
		}
		store[a.Label] = v
	}
	r := manifestReport{Claim: claim, AssertionStore: store, Signature: reportSignature(m)}
	// C2PA 1.x verifiable credentials store: one JSON credential per box.
	if vcs := m.Box.Child(labelCredentials); vcs != nil {
		for _, b := range vcs.Contents() {
			if !b.IsSuperbox() {
				continue
			}
			if c := b.Contents(); len(c) == 1 && c[0].Type == "json" {
				var v any
				if err := json.Unmarshal(c[0].Payload, &v); err != nil {
					return manifestReport{}, fmt.Errorf("credential %q: %w", b.Label(), err)
				}
				r.CredentialStore = append(r.CredentialStore, v)
			}
		}
	}
	return r, nil
}

// labelCredentials is the C2PA 1.x verifiable credentials store box.
const labelCredentials = "c2pa.credentials"

// hashesAsBase64 renders the hash of each hashed-URI map ({"url", "hash"})
// as base64, as c2patool does where a file stores it as an array of
// integers (older c2pa-rs, and JSON assertions).
func hashesAsBase64(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["url"].(string); ok {
			if b, ok := byteArray(x["hash"]); ok {
				x["hash"] = base64.StdEncoding.EncodeToString(b)
			}
		}
		for k, e := range x {
			x[k] = hashesAsBase64(e)
		}
	case []any:
		for i, e := range x {
			x[i] = hashesAsBase64(e)
		}
	}
	return v
}

// byteArray reads a non-empty array of integers 0-255.
func byteArray(v any) ([]byte, bool) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	out := make([]byte, 0, len(list))
	for _, e := range list {
		var n int64
		switch x := e.(type) {
		case uint64:
			n = int64(min(x, 256))
		case int64:
			n = x
		case json.Number:
			i, err := x.Int64()
			if err != nil {
				return nil, false
			}
			n = i
		default:
			return nil, false
		}
		if n < 0 || n > 255 {
			return nil, false
		}
		out = append(out, byte(n))
	}
	return out, true
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
		return hashesAsBase64(v), err
	case "json":
		d := json.NewDecoder(bytes.NewReader(c[0].Payload))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		return hashesAsBase64(v), nil
	case "bfdb":
		if len(c) == 2 && c[1].Type == "bidb" {
			return fmt.Sprintf("<omitted> len = %d", len(c[1].Payload)), nil
		}
	}
	return nil, nil
}

func reportSignature(m *manifest.Manifest) signatureReport {
	s := m.Signature
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
	if t, ok := verify.SigningTime(m); ok {
		str := rfc3339(t)
		r.Time = &str
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
