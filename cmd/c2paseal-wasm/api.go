// Command c2paseal-wasm is C2paSeal compiled to WebAssembly for browsers.
//
// Build it with
//
//	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o c2paseal.wasm ./cmd/c2paseal-wasm
//
// and load it with the wasm_exec.js that ships with the same Go version
// ($(go env GOROOT)/lib/wasm/wasm_exec.js):
//
//	const go = new Go();
//	const { instance } = await WebAssembly.instantiateStreaming(fetch("c2paseal.wasm"), go.importObject);
//	go.run(instance);              // defines globalThis.c2paseal
//	const r = JSON.parse(c2paseal.verify(bytes, { trustAnchors: pem }));
//
// globalThis.c2paseal then has:
//
//	verify(bytes, opts) → JSON string, the shape of `c2paseal verify --json`:
//	    {"validation_results": {...}, "validation_state": "Valid"}
//	  opts (all optional):
//	    trustAnchors  string      PEM trust anchors, such as the C2PA trust list
//	    allowedList   string      allowed list (PEM certificates or base64 SHA-256 lines)
//	    trustConfig   string      extra EKU OIDs, one per line
//	    manifestStore Uint8Array  a manifest store kept outside the file
//
//	sign(bytes, opts) → JSON string, the shape of `c2paseal sign --json`
//	  without the file paths, plus the signed file:
//	    {"format": "jpeg", "active_manifest": "urn:c2pa:…", "manifests": 1,
//	     "time_stamped": false, "ocsp_stapled": false, "data": "<base64>"}
//	  opts:
//	    cert          string      PEM chain, signer first (required)
//	    key           string      PEM private key, ECDSA P-256 (required)
//	    title         string      dc:title for the claim
//	    sourceType    string      IPTC digital source type
//	    noHistory     boolean     replace an existing manifest store
//	    ocspResponse  Uint8Array  DER OCSP response to staple
//
//	version() → JSON string, the shape of `c2paseal version --json`
//
// Bytes are Uint8Arrays. A bad option or a file that cannot be signed gives
// {"error": "..."}, as the CLI does with --json; a malformed or tampered
// file given to verify is reported in its validation results, not as an
// error. The browser build makes no network requests: there is no
// time-stamping, no remote manifest fetching and no online OCSP.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// verifyOptions are the options of verify(bytes, opts).
type verifyOptions struct {
	TrustAnchors  string
	AllowedList   string
	TrustConfig   string
	ManifestStore []byte
}

// signOptions are the options of sign(bytes, opts).
type signOptions struct {
	Cert, Key    string
	Title        string
	SourceType   string
	NoHistory    bool
	OCSPResponse []byte
}

// verifyResult is the JSON of `c2paseal verify --json` for one file.
type verifyResult struct {
	Results *verify.Result `json:"validation_results"`
	State   verify.State   `json:"validation_state"`
}

// signResult is the JSON of `c2paseal sign --json` without the paths, plus
// the signed bytes.
type signResult struct {
	Format         string `json:"format"`
	ActiveManifest string `json:"active_manifest"`
	TimeStamped    bool   `json:"time_stamped"`
	Manifests      int    `json:"manifests"`
	OCSPStapled    bool   `json:"ocsp_stapled"`
	Data           []byte `json:"data"`
}

// verifyJSON verifies b and returns the JSON for verify().
func verifyJSON(b []byte, o verifyOptions) []byte {
	opts := &c2paseal.VerifyOptions{ManifestStore: o.ManifestStore}
	if o.TrustAnchors != "" {
		anchors, err := c2paseal.ParseTrustAnchors([]byte(o.TrustAnchors))
		if err != nil {
			return errorJSON(fmt.Errorf("trustAnchors: %w", err))
		}
		opts.TrustAnchors = anchors
	}
	if o.AllowedList != "" {
		list, err := c2paseal.ParseAllowedList([]byte(o.AllowedList))
		if err != nil {
			return errorJSON(fmt.Errorf("allowedList: %w", err))
		}
		opts.AllowedList = list
	}
	if o.TrustConfig != "" {
		opts.ExtraEKUs = c2paseal.ParseTrustConfig([]byte(o.TrustConfig))
	}
	r := c2paseal.VerifyBytes(b, opts)
	return marshal(verifyResult{r, r.State()})
}

// signJSON signs b and returns the JSON for sign().
func signJSON(b []byte, o signOptions) []byte {
	if o.Cert == "" || o.Key == "" {
		return errorJSON(errors.New("sign: cert and key are required"))
	}
	chain, signer, err := c2paseal.ParseSigner([]byte(o.Cert), []byte(o.Key))
	if err != nil {
		return errorJSON(err)
	}
	signed, err := c2paseal.SignBytes(b, &c2paseal.SignOptions{
		Chain: chain, Signer: signer, Title: o.Title, DigitalSourceType: o.SourceType,
		NoHistory: o.NoHistory, OCSPResponse: o.OCSPResponse,
	})
	if err != nil {
		return errorJSON(err)
	}
	s, err := c2paseal.ReadBytes(signed)
	if err != nil {
		return errorJSON(err)
	}
	return marshal(signResult{
		Format: s.Format, ActiveManifest: s.Active.Label, Manifests: len(s.Manifests),
		OCSPStapled: len(s.Active.Signature.OCSP) > 0, Data: signed,
	})
}

// versionJSON returns the JSON for version().
func versionJSON() []byte {
	version, goVersion := "(devel)", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion
		if bi.Main.Version != "" {
			version = bi.Main.Version
		}
	}
	return marshal(map[string]string{"version": version, "go": goVersion})
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return errorJSON(err)
	}
	return b
}

func errorJSON(err error) []byte {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return b
}
