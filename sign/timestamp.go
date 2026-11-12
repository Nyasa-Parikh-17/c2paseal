package sign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/digitorus/timestamp"
)

// Time-stamp slot sizing.
//
// The RFC 3161 token goes into the COSE unprotected header as sigTst2
// (C2PA 2.4 §10.3.2.5). It time-stamps the signature, so it can only be
// fetched after signing, which is long after the manifest's size was fixed
// and the file was hashed. Its length also varies with the TSA (certificate
// chain, policy, serial number size). So the token cannot be fetched before
// sizing; instead build reserves a fixed-size unprotected header:
//
//	{"pad": bstr(n), "sigTst2": {"tstTokens": [{"val": token}]}}
//
// and the zero-filled "pad" byte string (the same header key c2pa-rs uses
// for this) absorbs the difference between the reserved token size and the
// real one. The pad is kept at minPad bytes or more, so its CBOR length head
// is always 3 bytes (0x59 + uint16) and every token size up to the reserve
// can be matched exactly. The unprotected header is not signed, so the
// padding changes nothing that is verified.
const (
	// DefaultTimestampReserve is the largest token, in bytes, that fits
	// when Options.TimestampReserve is zero. Tokens from public TSAs that
	// embed their certificate chain are usually 3-7 KB.
	DefaultTimestampReserve = 10 * 1024
	// MaxTimestampReserve bounds Options.TimestampReserve so the pad's
	// length always fits the 3-byte CBOR head.
	MaxTimestampReserve = 60000

	minPad              = 256
	maxPad              = 0xFFFF
	defaultTSATimeout   = 30 * time.Second
	maxTSAResponseBytes = 1 << 20
)

// Time-stamp errors.
var (
	// ErrTimestamp wraps every failure to obtain a usable time-stamp token.
	ErrTimestamp = errors.New("sign: time-stamp")
	// ErrTimestampTooLarge means the TSA's token does not fit the reserved
	// slot; raise Options.TimestampReserve.
	ErrTimestampTooLarge = errors.New("sign: time-stamp token larger than the reserved slot")
)

// tstHeader returns the unprotected header holding token and the extra
// entries (a stapled OCSP response), padded so that it encodes to exactly
// size bytes. size 0 means no time-stamp: only the extra entries.
func tstHeader(token []byte, size int, extra map[any]any) (map[any]any, error) {
	h := map[any]any{}
	for k, v := range extra {
		h[k] = v
	}
	if size == 0 {
		return h, nil
	}
	h["sigTst2"] = map[string]any{"tstTokens": []any{map[string]any{"val": token}}}
	h["pad"] = make([]byte, minPad)
	b, err := cbormode.Enc.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("sign: encode time-stamp header: %w", err)
	}
	pad := minPad + size - len(b)
	if pad < minPad {
		return nil, fmt.Errorf("%w: token %d bytes", ErrTimestampTooLarge, len(token))
	}
	if pad > maxPad {
		return nil, fmt.Errorf("%w: time-stamp pad %d bytes", ErrSizeMismatch, pad)
	}
	h["pad"] = make([]byte, pad)
	if b, err = cbormode.Enc.Marshal(h); err != nil {
		return nil, fmt.Errorf("sign: encode time-stamp header: %w", err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: time-stamp header %d bytes, reserved %d", ErrSizeMismatch, len(b), size)
	}
	return h, nil
}

// tstHeaderSize is the reserved unprotected header size for tokens of up to
// reserve bytes, with the extra entries.
func tstHeaderSize(reserve int, extra map[any]any) (int, error) {
	h := map[any]any{
		"sigTst2": map[string]any{"tstTokens": []any{map[string]any{"val": make([]byte, reserve)}}},
		"pad":     make([]byte, minPad),
	}
	for k, v := range extra {
		h[k] = v
	}
	b, err := cbormode.Enc.Marshal(h)
	if err != nil {
		return 0, fmt.Errorf("sign: encode time-stamp header: %w", err)
	}
	return len(b), nil
}

// counterSignatureData is what a sigTst2 token's message imprint covers: the
// COSE CounterSignature structure over the signature as a CBOR byte string
// (C2PA 2.4 §10.3.2.5, as c2pa-rs and verify/timestamp.go compute it).
func (m *Manifest) counterSignatureData(sig []byte) ([]byte, error) {
	sigBstr, err := cbormode.Enc.Marshal(sig)
	if err != nil {
		return nil, err
	}
	return cbormode.Enc.Marshal([]any{"CounterSignature", m.protected, []byte{}, sigBstr})
}

// fetchTimestamp requests an RFC 3161 token over data's SHA-256 from the TSA
// and checks that the response answers this request.
func (o *Options) fetchTimestamp(data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("%w: nonce: %w", ErrTimestamp, err)
	}
	req := timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: sum[:], Certificates: true, Nonce: nonce}
	body, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrTimestamp, err)
	}
	hreq, err := http.NewRequest(http.MethodPost, o.TSAURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTimestamp, err)
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	hreq.Header.Set("Accept", "application/timestamp-reply")
	client := o.TSAClient
	if client == nil {
		client = &http.Client{Timeout: defaultTSATimeout}
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTimestamp, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: TSA answered HTTP %s", ErrTimestamp, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", ErrTimestamp, err)
	}
	if len(b) > maxTSAResponseBytes {
		return nil, fmt.Errorf("%w: response larger than %d bytes", ErrTimestamp, maxTSAResponseBytes)
	}

	// ParseResponse rejects non-granted statuses and checks the token's CMS
	// signature against the certificates it embeds.
	ts, err := timestamp.ParseResponse(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTimestamp, err)
	}
	switch {
	case ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, sum[:]):
		return nil, fmt.Errorf("%w: token does not cover the signature", ErrTimestamp)
	case ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0:
		return nil, fmt.Errorf("%w: token nonce does not match the request", ErrTimestamp)
	case len(ts.Certificates) == 0:
		// Validators need the TSA certificate in the token to check it.
		return nil, fmt.Errorf("%w: token carries no TSA certificate", ErrTimestamp)
	case len(ts.RawToken) > o.timestampReserve():
		return nil, fmt.Errorf("%w: token %d bytes, reserve %d", ErrTimestampTooLarge, len(ts.RawToken), o.timestampReserve())
	}
	return ts.RawToken, nil
}
