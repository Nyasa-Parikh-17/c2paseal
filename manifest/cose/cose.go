package cose

import (
	"errors"
	"fmt"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/fxamacker/cbor/v2"
)

// COSE header labels and values used by C2PA.
const (
	HeaderAlg     = 1
	HeaderX5Chain = 33 // RFC 9360

	AlgES256 = -7

	tagSign1 = 18
)

// Unprotected header keys for RFC 3161 time-stamps: sigTst2 (C2PA 2.x)
// time-stamps the signature, sigTst (1.x) the payload.
const (
	HeaderSigTst  = "sigTst"
	HeaderSigTst2 = "sigTst2"
)

// ErrMalformed wraps every decode error.
var ErrMalformed = errors.New("malformed COSE_Sign1")

// Sign1 is a decoded, unverified COSE_Sign1 claim signature.
type Sign1 struct {
	Raw         []byte      // the whole COSE_Sign1 encoding
	Protected   []byte      // serialised protected header, as signed
	Headers     map[any]any // decoded protected header
	Unprotected map[any]any
	Payload     []byte // nil: detached (C2PA signs the claim bytes)
	Signature   []byte

	Alg        int64    // from the protected header
	X5Chain    [][]byte // DER certificates, signer first
	Timestamps []Timestamp
}

// Timestamp is an RFC 3161 time-stamp token from the unprotected header.
type Timestamp struct {
	Version int    // 2 for sigTst2, 1 for sigTst
	Token   []byte // DER TimeStampToken
}

type sign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

// Decode decodes a tagged (18) or untagged COSE_Sign1 message.
func Decode(b []byte) (*Sign1, error) {
	fail := func(format string, args ...any) (*Sign1, error) {
		return nil, fmt.Errorf("cose: %w: %s", ErrMalformed, fmt.Sprintf(format, args...))
	}
	body := b
	var tag cbor.RawTag
	if err := cbormode.Dec.Unmarshal(b, &tag); err == nil {
		if tag.Number != tagSign1 {
			return fail("CBOR tag %d, want %d", tag.Number, tagSign1)
		}
		body = tag.Content
	}
	var m sign1
	if err := cbormode.Dec.Unmarshal(body, &m); err != nil {
		return fail("%v", err)
	}
	s := &Sign1{Raw: b, Protected: m.Protected, Unprotected: m.Unprotected, Payload: m.Payload, Signature: m.Signature}
	if len(m.Protected) == 0 {
		return fail("empty protected header")
	}
	if err := cbormode.Dec.Unmarshal(m.Protected, &s.Headers); err != nil {
		return fail("protected header: %v", err)
	}

	alg, ok := intValue(lookup(s.Headers, HeaderAlg))
	if !ok {
		return fail("protected header has no integer alg")
	}
	s.Alg = alg

	// C2PA 2.x puts x5chain in the protected header; 1.x allowed unprotected.
	chain := lookup(s.Headers, HeaderX5Chain)
	if chain == nil {
		chain = lookup(s.Unprotected, HeaderX5Chain)
	}
	switch c := chain.(type) {
	case []byte:
		s.X5Chain = [][]byte{c}
	case []any:
		for _, der := range c {
			d, ok := der.([]byte)
			if !ok {
				return fail("x5chain entry is not a byte string")
			}
			s.X5Chain = append(s.X5Chain, d)
		}
	case nil:
		return fail("no x5chain header")
	default:
		return fail("x5chain is %T", chain)
	}
	if len(s.X5Chain) == 0 {
		return fail("empty x5chain")
	}

	for _, h := range []struct {
		key     string
		version int
	}{{HeaderSigTst2, 2}, {HeaderSigTst, 1}} {
		tokens, err := tstTokens(lookup(s.Unprotected, h.key))
		if err != nil {
			return fail("%s: %v", h.key, err)
		}
		for _, t := range tokens {
			s.Timestamps = append(s.Timestamps, Timestamp{Version: h.version, Token: t})
		}
	}
	return s, nil
}

// tstTokens reads {"tstTokens": [{"val": bstr}, …]}.
func tstTokens(v any) ([][]byte, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not a map")
	}
	list, ok := m["tstTokens"].([]any)
	if !ok {
		return nil, errors.New("no tstTokens array")
	}
	var out [][]byte
	for _, e := range list {
		em, ok := e.(map[string]any)
		if !ok {
			return nil, errors.New("tstTokens entry is not a map")
		}
		val, ok := em["val"].([]byte)
		if !ok {
			return nil, errors.New("tstTokens entry has no val byte string")
		}
		out = append(out, val)
	}
	return out, nil
}

// lookup finds a header by integer or text label.
func lookup(h map[any]any, label any) any {
	for k, v := range h {
		if ki, ok := intValue(k); ok {
			if li, ok := label.(int); ok && ki == int64(li) {
				return v
			}
		} else if k == label {
			return v
		}
	}
	return nil
}

func intValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n <= 1<<63-1 {
			return int64(n), true
		}
	}
	return 0, false
}

// AlgName returns the c2patool name of a COSE algorithm ("es256"), or "".
func AlgName(alg int64) string {
	switch alg {
	case AlgES256:
		return "es256"
	case -35:
		return "es384"
	case -36:
		return "es512"
	case -37:
		return "ps256"
	case -38:
		return "ps384"
	case -39:
		return "ps512"
	case -8:
		return "ed25519"
	}
	return ""
}
