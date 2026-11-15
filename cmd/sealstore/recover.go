package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark/wmfile"
)

// recovery is the result of recovering a copy's credentials.
type recovery struct {
	// Recovered is true when the manifest was found and its signature
	// validates: the credentials are this image's, though the copy's bytes
	// may have changed since (ContentChanged).
	Recovered   bool    `json:"recovered"`
	WatermarkID string  `json:"watermark_id,omitempty"`
	Confidence  float64 `json:"watermark_confidence,omitempty"`
	StoreURL    string  `json:"store_url,omitempty"`
	// SignatureValid: the claim signature validates and nothing fails
	// except the hard binding and, without trust anchors, the trust check.
	SignatureValid bool `json:"signature_valid"`
	Trusted        bool `json:"trusted"`
	// ContentChanged: the copy's bytes are not the signed file's (the hard
	// binding does not match), as after re-encoding or resizing.
	ContentChanged bool           `json:"content_changed"`
	ActiveManifest string         `json:"active_manifest,omitempty"`
	Signer         string         `json:"signer,omitempty"`
	Issuer         string         `json:"issuer,omitempty"`
	SignedAt       string         `json:"signed_at,omitempty"`
	Results        *verify.Result `json:"validation_results,omitempty"`
	State          verify.State   `json:"validation_state,omitempty"`
	Problem        string         `json:"problem,omitempty"`
}

// expectedFailures are the failures a recovered copy may show: its bytes
// changed (so the hard binding cannot match), and, without trust anchors,
// the signer is untrusted.
var expectedFailures = []string{verify.AssertionDataHashMismatch, verify.AssertionBMFFHashMismatch, verify.SigningCredentialUntrusted}

// fetch gets the manifest store for id from a sealstore server.
func fetch(ctx context.Context, client *http.Client, storeURL string, id watermark.ID) ([]byte, error) {
	u := strings.TrimRight(storeURL, "/") + "/v1/manifests/" + id.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("store answered %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// recoverCredentials reads the watermark from file, fetches the manifest
// store for it, and verifies the file against that store.
func recoverCredentials(ctx context.Context, client *http.Client, file []byte, storeURL string, anchors []*x509.Certificate) recovery {
	rc := recovery{StoreURL: storeURL}
	img, _, err := wmfile.Decode(file)
	if err != nil {
		rc.Problem = err.Error()
		return rc
	}
	wm, err := watermark.Extract(img)
	if err != nil {
		rc.Problem = "no watermark found in the image"
		if errors.Is(err, watermark.ErrTooSmall) {
			rc.Problem = err.Error()
		}
		return rc
	}
	rc.WatermarkID, rc.Confidence = wm.ID.String(), wm.Confidence
	store, err := fetch(ctx, client, storeURL, wm.ID)
	if err != nil {
		rc.Problem = "manifest store: " + err.Error()
		return rc
	}
	got, err := softBindingID(store)
	if err != nil || got != wm.ID {
		rc.Problem = fmt.Sprintf("the store's manifest does not record watermark %s", wm.ID)
		return rc
	}
	ms, err := c2paseal.ReadStore(store)
	if err != nil {
		rc.Problem = err.Error()
		return rc
	}
	rc.ActiveManifest = ms.Active.Label
	if j, err := json.Marshal(ms); err == nil {
		var rep struct {
			Manifests map[string]struct {
				Signature struct {
					CommonName string `json:"common_name"`
					Issuer     string `json:"issuer"`
					Time       string `json:"time"`
				} `json:"signature"`
			} `json:"manifests"`
		}
		if json.Unmarshal(j, &rep) == nil {
			sig := rep.Manifests[ms.Active.Label].Signature
			rc.Signer, rc.Issuer, rc.SignedAt = sig.CommonName, sig.Issuer, sig.Time
		}
	}
	r := c2paseal.VerifyBytes(file, &c2paseal.VerifyOptions{ManifestStore: store, TrustAnchors: anchors})
	rc.Results, rc.State = r, r.State()
	validated := false
	ok := true
	for _, s := range r.ActiveManifest {
		switch {
		case s.Code == verify.ClaimSignatureValidated:
			validated = true
		case s.Code == verify.SigningCredentialTrusted:
			rc.Trusted = true
		case s.Code == verify.AssertionDataHashMismatch || s.Code == verify.AssertionBMFFHashMismatch:
			rc.ContentChanged = true
		}
		if s.Kind() == verify.Failure && !slices.Contains(expectedFailures, s.Code) {
			ok = false
			if rc.Problem == "" {
				rc.Problem = s.Code + ": " + s.Explanation
			}
		}
	}
	rc.SignatureValid = validated && ok
	rc.Recovered = rc.SignatureValid
	return rc
}

// describe is the human-readable report of a recovery.
func (rc recovery) describe() string {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	if rc.WatermarkID != "" {
		p("watermark: %s (confidence %.2f)", rc.WatermarkID, rc.Confidence)
	}
	if !rc.Recovered {
		p("not recovered: %s", rc.Problem)
		return b.String()
	}
	p("recovered: manifest %s from %s", rc.ActiveManifest, rc.StoreURL)
	who := rc.Signer
	if rc.Issuer != "" && rc.Issuer != who {
		who += " (certificate issued by " + rc.Issuer + ")"
	}
	when := "at an unknown time (no time-stamp)"
	if rc.SignedAt != "" {
		if t, err := time.Parse(time.RFC3339, rc.SignedAt); err == nil {
			when = "at " + t.UTC().Format("2006-01-02 15:04 UTC") + " (time-stamp)"
		}
	}
	p("signed by %s %s; the signature is valid", who, when)
	if rc.Trusted {
		p("the signer is on your trust list")
	} else {
		p("the signer is not on your trust list (pass --trust to check it)")
	}
	if rc.ContentChanged {
		p("this copy is not the signed file: its bytes changed since signing (re-encoded, resized or edited), so only the watermark links it to these credentials")
	} else {
		p("this copy matches the signed file's hard binding")
	}
	return b.String()
}
