package sign

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/ocsp"
)

// ErrBadOCSP is returned when the OCSP response to staple cannot be used:
// it does not parse, is not successful, its signature does not verify, it
// says nothing about the signing certificate, or it cannot be fetched.
var ErrBadOCSP = errors.New("sign: OCSP response")

const defaultOCSPTimeout = 30 * time.Second

// staple returns the OCSP response to store in the COSE unprotected header
// (rVals.ocspVals, C2PA 2.4 §10.3.2.6): Options.OCSPResponse, or one fetched
// from the signer certificate's responder with Options.FetchOCSP; nil if
// neither is set. The response must answer for the signing certificate;
// its status (good, revoked or unknown) is stored as the responder gave it.
func (o *Options) staple() ([]byte, error) {
	der := o.OCSPResponse
	if der == nil && !o.FetchOCSP {
		return nil, nil
	}
	if len(o.Chain) < 2 {
		return nil, fmt.Errorf("%w: the chain needs the signer's issuer", ErrBadOCSP)
	}
	if der == nil {
		client := o.OCSPClient
		if client == nil {
			client = &http.Client{Timeout: defaultOCSPTimeout}
		}
		var err error
		if der, err = ocsp.Fetch(client, o.Chain[0], o.Chain[1]); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadOCSP, err)
		}
	}
	r, err := ocsp.ParseResponse(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadOCSP, err)
	}
	if r.Status != 0 {
		return nil, fmt.Errorf("%w: response status %d, not successful", ErrBadOCSP, r.Status)
	}
	if err := r.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadOCSP, err)
	}
	if r.Find(o.Chain[0], o.Chain[1]) == nil {
		return nil, fmt.Errorf("%w: no answer for the signing certificate", ErrBadOCSP)
	}
	return der, nil
}

// rValsHeader is the unprotected header entry for a stapled response.
func rValsHeader(der []byte) map[string]any {
	return map[string]any{"ocspVals": []any{der}}
}
