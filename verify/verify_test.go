package verify

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	"github.com/digitorus/timestamp"
	gocose "github.com/veraison/go-cose"
)

// tsa returns a test time-stamping certificate issued by the test root.
func tsa(t *testing.T) (*x509.Certificate, crypto.Signer) {
	return tsaValid(t, t0.AddDate(-1, 0, 0), t0.AddDate(3, 0, 0))
}

// tsaValid returns a test time-stamping certificate valid in [from, to].
func tsaValid(t *testing.T, from, to time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	root, rootKey := ca(t)
	key := newKey(t)
	cert := create(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "Test TSA", Organization: []string{"Test"}},
		NotBefore:   from,
		NotAfter:    to,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}, root, &key.PublicKey, rootKey)
	return cert, key
}

// tsaOpts changes how token makes a token.
type tsaOpts struct {
	cert        *x509.Certificate // with key; default tsa(t)
	key         crypto.Signer
	signingTime *time.Time              // CMS signingTime attribute; nil: none
	noCerts     bool                    // leave the certificates out
	noAttrs     bool                    // no signed attributes: sign the TSTInfo itself
	noDigest    bool                    // signed attributes without messageDigest
	badDigest   bool                    // messageDigest that does not match the TSTInfo
	wrongSID    bool                    // signer identifier names no embedded certificate
	digitorus   bool                    // make the token with digitorus/timestamp instead
	mutate      func(tok []byte) []byte // applied to the finished token
	v1          bool                    // stamped: a v1 claim with a sigTst header
}

var (
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// token makes an RFC 3161 token over data's SHA-256 with genTime at.
func token(t *testing.T, data []byte, at time.Time, opts ...tsaOpts) []byte {
	t.Helper()
	var o tsaOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	cert, key := o.cert, o.key
	if cert == nil {
		cert, key = tsa(t)
	}
	var tok []byte
	if o.digitorus {
		tok = digitorusToken(t, cert, key, data, at)
	} else {
		tok = buildToken(t, cert, key, data, at, o)
	}
	if o.mutate != nil {
		return o.mutate(bytes.Clone(tok))
	}
	return tok
}

// digitorusToken makes a token with digitorus/timestamp, independently of
// buildToken. Its CMS signingTime is the real current time.
func digitorusToken(t *testing.T, cert *x509.Certificate, key crypto.Signer, data []byte, at time.Time) []byte {
	t.Helper()
	sum := sha256.Sum256(data)
	ts := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     sum[:],
		Time:              at,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      big.NewInt(42),
		AddTSACertificate: true,
	}
	resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RawToken
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildToken writes a CMS SignedData time-stamp token by hand (ECDSA
// P-256, SHA-256), so tests control every field.
func buildToken(t *testing.T, cert *x509.Certificate, key crypto.Signer, data []byte, at time.Time, o tsaOpts) []byte {
	t.Helper()
	sum := sha256.Sum256(data)
	info := mustMarshal(t, tstInfo{
		Version:        1,
		Policy:         asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: sum[:]},
		SerialNumber:   big.NewInt(42),
		Time:           at.UTC(),
	})

	type attr struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	value := func(v any) asn1.RawValue { return asn1.RawValue{FullBytes: mustMarshal(t, v)} }
	var attrs []byte
	if !o.noAttrs {
		attrs = append(attrs, mustMarshal(t, attr{oidContentType, []asn1.RawValue{value(oidTSTInfo)}})...)
		if !o.noDigest {
			md := sha256.Sum256(info)
			if o.badDigest {
				md[0] ^= 1
			}
			attrs = append(attrs, mustMarshal(t, attr{oidMessageDigest, []asn1.RawValue{value(md[:])}})...)
		}
		if o.signingTime != nil {
			attrs = append(attrs, mustMarshal(t, attr{oidSigningTime, []asn1.RawValue{value(o.signingTime.UTC())}})...)
		}
	}
	tbs := info
	var signedAttrs asn1.RawValue
	if !o.noAttrs {
		tbs = mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrs})
		signedAttrs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs}
	}
	h := sha256.Sum256(tbs)
	sig, err := key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	serial := new(big.Int).Set(cert.SerialNumber)
	if o.wrongSID {
		serial.Add(serial, big.NewInt(1000))
	}
	type sInfo struct {
		Version            int
		SID                issuerAndSerial
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        asn1.RawValue `asn1:"optional"`
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}
	si := sInfo{
		Version:            1,
		SID:                issuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: serial},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA2},
		Signature:          sig,
	}
	// Explicit [0] wrappers are written by hand: encoding/asn1 does not add
	// them around a RawValue.
	explicit0 := func(inner []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
	}
	type encap struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue
	}
	type sData struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		EncapContent     encap
		Certificates     asn1.RawValue `asn1:"optional"`
		SignerInfos      []sInfo       `asn1:"set"`
	}
	sd := sData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContent:     encap{oidTSTInfo, explicit0(mustMarshal(t, info))},
		SignerInfos:      []sInfo{si},
	}
	if !o.noCerts {
		sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw}
	}
	return mustMarshal(t, struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, explicit0(mustMarshal(t, sd))})
}

// stamped signs claimBytes like signedManifest and adds a sigTst2 header
// holding the given tokens, plus (if overRealData) one made over the real
// countersignature data.
func stamped(t *testing.T, leaf *x509.Certificate, key crypto.Signer, at time.Time, tokens [][]byte, overRealData bool, opts ...tsaOpts) *manifest.Manifest {
	t.Helper()
	v1 := len(opts) > 0 && opts[0].v1
	signer, err := gocose.NewSigner(gocose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	msg := gocose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(gocose.AlgorithmES256)
	msg.Headers.Protected[gocose.HeaderLabelX5Chain] = [][]byte{leaf.Raw}
	msg.Payload = claimBytes
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	msg.Payload = nil
	if overRealData {
		protected, err := msg.Headers.MarshalProtected()
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := cbormode.Dec.Unmarshal(protected, &raw); err != nil {
			t.Fatal(err)
		}
		data, _ := cbormode.Enc.Marshal(msg.Signature)
		if v1 { // sigTst covers the claim itself
			data = claimBytes
		}
		tbs, _ := cbormode.Enc.Marshal([]any{"CounterSignature", raw, []byte{}, data})
		tokens = append(tokens, token(t, tbs, at, opts...))
	}
	var list []any
	for _, tok := range tokens {
		list = append(list, map[string]any{"val": tok})
	}
	header := "sigTst2"
	if v1 {
		header = "sigTst"
	}
	msg.Headers.Unprotected[header] = map[string]any{"tstTokens": list}
	b, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	s, err := cose.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	const label = "urn:c2pa:3fa85f64-5717-4562-b3fc-2c963f66afa6"
	m := &manifest.Manifest{
		Label:     label,
		Claim:     &manifest.Claim{Signature: "self#jumbf=/c2pa/" + label + "/c2pa.signature", Raw: claimBytes},
		Signature: s,
	}
	if v1 {
		m.Claim.Version = 1
	}
	return m
}

// TestTimeStamp: a valid, trusted time-stamp's time is used for the signer
// checks, so a signer that has since expired is still fine; an untrusted or
// mismatching one is reported but its time is ignored.
func TestTimeStamp(t *testing.T) {
	root, rootKey := ca(t)
	key := newKey(t)
	leaf := create(t, leafTemplate(), root, &key.PublicKey, rootKey) // valid during 2026
	stampTime := t0.AddDate(0, 3, 0)
	later := func() time.Time { return t0.AddDate(2, 0, 0) } // signer expired by now
	trustAll := &Options{TrustAnchors: []*x509.Certificate{root}, Now: later}
	trustNone := &Options{Now: later}
	farFuture := t0.AddDate(5, 0, 0)
	now := time.Now()
	nowTSA, nowTSAKey := tsaValid(t, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0))

	tests := []struct {
		name string
		m    *manifest.Manifest
		opts *Options
		want []string
	}{
		{"trusted TSA", stamped(t, leaf, key, stampTime, nil, true), trustAll,
			[]string{TimeStampValidated, TimeStampTrusted, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"untrusted TSA", stamped(t, leaf, key, stampTime, nil, true), trustNone,
			[]string{TimeStampValidated, TimeStampUntrusted, SigningCredentialExpired, SigningCredentialUntrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"imprint over other data", stamped(t, leaf, key, stampTime, [][]byte{token(t, []byte("other"), stampTime)}, false), trustAll,
			[]string{TimeStampMismatch, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"garbage token", stamped(t, leaf, key, stampTime, [][]byte{{0x30, 0x03, 1, 2, 3}}, false), trustAll,
			[]string{TimeStampMalformed, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"two tokens", stamped(t, leaf, key, stampTime, [][]byte{{1}}, true), trustAll,
			[]string{TimeStampMalformed, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"TSA cert expired at stamp time", stamped(t, leaf, key, t0.AddDate(5, 0, 0), nil, true), trustAll,
			[]string{TimeStampOutsideValidity, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},

		// The CMS signingTime attribute takes the place of genTime.
		{"signingTime inside, genTime outside", stamped(t, leaf, key, t0.AddDate(5, 0, 0), nil, true, tsaOpts{signingTime: &stampTime}), trustAll,
			[]string{TimeStampValidated, TimeStampTrusted, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"signingTime outside, genTime inside", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{signingTime: &farFuture}), trustAll,
			[]string{TimeStampOutsideValidity, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},

		// A CMS signature that does not verify is untrusted, not malformed.
		{"bad CMS signature", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{mutate: flipLast}), trustAll,
			[]string{TimeStampUntrusted, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"no certificates", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{noCerts: true}), trustAll,
			[]string{TimeStampUntrusted, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"messageDigest mismatch", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{badDigest: true}), trustAll,
			[]string{TimeStampMismatch, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"no messageDigest", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{noDigest: true}), trustAll,
			[]string{TimeStampMalformed, SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"no signed attributes", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{noAttrs: true}), trustAll,
			[]string{TimeStampValidated, TimeStampTrusted, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		// c2pa-rs logs nothing when no SignerInfo names an embedded certificate.
		{"signer certificate not embedded", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{wrongSID: true}), trustAll,
			[]string{SigningCredentialExpired, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
		{"TimeStampResp instead of a token", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{mutate: asResponse}), trustAll,
			[]string{TimeStampValidated, TimeStampTrusted, SigningCredentialTrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},

		// v1 claims (sigTst): the authority's trust is not checked.
		{"v1, untrusted TSA", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{v1: true}), trustNone,
			[]string{TimeStampValidated, TimeStampTrusted, SigningCredentialUntrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},

		// A digitorus/timestamp token, whose signingTime is the real time.
		{"digitorus token", stamped(t, leaf, key, stampTime, nil, true, tsaOpts{digitorus: true, cert: nowTSA, key: nowTSAKey}), trustNone,
			[]string{TimeStampValidated, TimeStampUntrusted, SigningCredentialExpired, SigningCredentialUntrusted, ClaimSignatureInsideValidity, ClaimSignatureValidated}},
	}
	for _, tt := range tests {
		if got := codes(checkClaim(tt.m, tt.opts)); !slices.Equal(got, tt.want) {
			t.Errorf("%s:\n got  %q\n want %q", tt.name, got, tt.want)
		}
	}
}

func flipLast(b []byte) []byte { b[len(b)-1] ^= 1; return b }

// asResponse wraps a token in a granted TimeStampResp.
func asResponse(tok []byte) []byte {
	b, err := asn1.Marshal(struct {
		Status struct{ Status int }
		Token  asn1.RawValue
	}{Token: asn1.RawValue{FullBytes: tok}})
	if err != nil {
		panic(err)
	}
	return b
}

// assertionBox builds an assertion superbox with a CBOR content box.
func assertionBox(t *testing.T, label string, v any) *jumbf.Box {
	t.Helper()
	b, err := cbormode.Enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return &jumbf.Box{Type: jumbf.TypeSuperbox, Children: []*jumbf.Box{
		{Type: jumbf.TypeDescription, Description: &jumbf.Description{Toggles: jumbf.ToggleLabel, Label: label}},
		{Type: "cbor", Payload: b},
	}}
}

// withAssertions makes a manifest whose claim references the given
// assertions (all created) with correct hashes.
func withAssertions(t *testing.T, boxes ...*jumbf.Box) *manifest.Manifest {
	t.Helper()
	m := &manifest.Manifest{Label: "urn:c2pa:3fa85f64-5717-4562-b3fc-2c963f66afa6", Claim: &manifest.Claim{Alg: "sha256"}}
	for _, b := range boxes {
		a := assertion.Decode(b)
		m.Assertions = append(m.Assertions, a)
		sum, _ := manifest.HashBox("sha256", b)
		ref := manifest.HashedURI{URL: "self#jumbf=c2pa.assertions/" + a.Label, Hash: sum}
		m.Claim.CreatedAssertions = append(m.Claim.CreatedAssertions, ref)
		m.HashChecks = append(m.HashChecks, manifest.URICheck{Ref: ref, Alg: "sha256", Box: b, Match: true})
	}
	return m
}

func act(name string, extra map[string]any) map[string]any {
	a := map[string]any{"action": name}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func TestActions(t *testing.T) {
	src := map[string]any{"digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}
	ingr := map[string]any{"parameters": map[string]any{"ingredients": []any{map[string]any{"url": "x"}}}}
	actionList := func(acts ...any) map[string]any { return map[string]any{"actions": acts} }
	tests := []struct {
		name  string
		boxes []*jumbf.Box
		want  []string
	}{
		{"created", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2", actionList(act("c2pa.created", src)))}, nil},
		{"opened with ingredients", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2", actionList(act("c2pa.opened", ingr)))}, nil},
		{"first action edited", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2", actionList(act("c2pa.edited", nil)))},
			[]string{AssertionActionMalformed}},
		{"created without source type", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2", actionList(act("c2pa.created", nil)))},
			[]string{AssertionActionMalformed}},
		{"opened without ingredients", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2", actionList(act("c2pa.opened", nil)))},
			[]string{AssertionActionIngredientMismatch}},
		{"opened with empty ingredients", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2",
			actionList(act("c2pa.opened", map[string]any{"parameters": map[string]any{"ingredients": []any{}}})))},
			[]string{AssertionActionIngredientMismatch}},
		{"empty actions", []*jumbf.Box{assertionBox(t, "c2pa.actions.v2", actionList())}, []string{AssertionActionMalformed}},
		{"created in second assertion", []*jumbf.Box{
			assertionBox(t, "c2pa.actions.v2", actionList(act("c2pa.created", src))),
			assertionBox(t, "c2pa.actions.v2__1", actionList(act("c2pa.created", src))),
		}, []string{AssertionActionMalformed, AssertionActionMalformed}},
		{"no actions assertion", nil, nil},
	}
	for _, tt := range tests {
		if got := codes(actions(withAssertions(t, tt.boxes...))); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAssertionRefs(t *testing.T) {
	m := withAssertions(t, assertionBox(t, "a", 1), assertionBox(t, "b", 2))
	m.HashChecks[1].Match = false
	m.Assertions = append(m.Assertions, assertion.Decode(assertionBox(t, "extra", 3)))
	m.HashChecks = append(m.HashChecks,
		manifest.URICheck{Ref: manifest.HashedURI{URL: "self#jumbf=c2pa.assertions/gone"}, Err: manifest.ErrUnresolved},
		manifest.URICheck{Ref: manifest.HashedURI{URL: "self#jumbf=/c2pa/urn:c2pa:other/c2pa.assertions/x"}, Match: true},
		manifest.URICheck{Ref: manifest.HashedURI{URL: "self#jumbf=/elsewhere"}},
	)
	got, undeclared := assertionRefs(m)
	want := []string{AssertionHashedURIMatch, AssertionHashedURIMismatch, AssertionMissing,
		AssertionOutsideManifest, AssertionHashedURIMatch, AssertionHashedURIMismatch, AssertionUndeclared}
	if !slices.Equal(codes(got), want) || !undeclared {
		t.Errorf("got %q (undeclared %v), want %q", codes(got), undeclared, want)
	}
	if got[0].URL != assertionURL(m.Label, "a") {
		t.Errorf("match URL %q is not absolute", got[0].URL)
	}
}

func TestHardBinding(t *testing.T) {
	file := []byte("0123456789abcdefghij")
	hashOf := func(parts ...string) []byte {
		h := sha256.New()
		for _, p := range parts {
			h.Write([]byte(p))
		}
		return h.Sum(nil)
	}
	dh := func(ex []map[string]any, hash []byte, extra map[string]any) *jumbf.Box {
		v := map[string]any{"exclusions": ex, "name": "jumbf manifest", "hash": hash, "pad": []byte{}}
		for k, x := range extra {
			v[k] = x
		}
		return assertionBox(t, "c2pa.hash.data", v)
	}
	ex := func(start, length int) map[string]any { return map[string]any{"start": start, "length": length} }

	tests := []struct {
		name  string
		boxes []*jumbf.Box
		want  []string
	}{
		{"match", []*jumbf.Box{dh([]map[string]any{ex(5, 5)}, hashOf("01234", "abcdefghij"), nil)}, []string{AssertionDataHashMatch}},
		{"no exclusions", []*jumbf.Box{dh(nil, hashOf(string(file)), nil)}, []string{AssertionDataHashMatch}},
		{"two exclusions", []*jumbf.Box{dh([]map[string]any{ex(15, 5), ex(0, 2)}, hashOf("23456789abcde"), nil)},
			[]string{AssertionDataHashExtra, AssertionDataHashMatch}},
		{"mismatch", []*jumbf.Box{dh([]map[string]any{ex(5, 5)}, hashOf("nope"), nil)}, []string{AssertionDataHashMismatch}},
		{"overlap", []*jumbf.Box{dh([]map[string]any{ex(0, 5), ex(3, 5)}, nil, nil)}, []string{AssertionDataHashExtra, AssertionDataHashMismatch}},
		{"past end", []*jumbf.Box{dh([]map[string]any{ex(15, 10)}, nil, nil)}, []string{AssertionDataHashMismatch}},
		{"remote", []*jumbf.Box{dh(nil, nil, map[string]any{"url": "https://x"})}, []string{AssertionDataHashMismatch}},
		{"malformed", []*jumbf.Box{assertionBox(t, "c2pa.hash.data", []int{1})}, []string{AssertionDataHashMalformed}},
		{"missing", nil, []string{ClaimHardBindingsMissing}},
		{"two bindings", []*jumbf.Box{dh(nil, hashOf(string(file)), nil), assertionBox(t, "c2pa.hash.boxes", map[string]any{})},
			[]string{AssertionMultipleHardBinding, AssertionDataHashMatch, GeneralError}},
	}
	for _, tt := range tests {
		if got := codes(hardBinding(withAssertions(t, tt.boxes...), file)); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestFileErrors(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	png := read("signed/small.png")
	// A second caBX chunk straight after the first.
	twoStores := append(append(append([]byte{}, png[:33+12+42942]...), png[33:33+12+42942]...), png[33+12+42942:]...)

	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, GeneralError},
		{"GIF", []byte("GIF89a"), GeneralError},
		{"unsigned", read("unsigned/small.jpg"), ClaimMissing},
		{"truncated APP11", read("broken/truncated-app11.jpg"), GeneralError},
		{"bad JUMBF length", read("broken/bad-jumbf-length.jpg"), ClaimMalformed},
		{"two caBX chunks", twoStores, ClaimMultiple},
	}
	for _, tt := range tests {
		r := File(tt.in, nil)
		if got := codes(r.ActiveManifest); !slices.Equal(got, []string{tt.want}) || r.State() != Invalid {
			t.Errorf("%s: %q state %s, want [%s] Invalid", tt.name, got, r.State(), tt.want)
		}
	}
}

func TestState(t *testing.T) {
	ok := []Status{{Code: ClaimSignatureInsideValidity}, {Code: ClaimSignatureValidated}}
	tests := []struct {
		name string
		r    Result
		want State
	}{
		{"valid untrusted", Result{ActiveManifest: append(slices.Clone(ok), Status{Code: SigningCredentialUntrusted})}, Valid},
		{"trusted", Result{ActiveManifest: append(slices.Clone(ok), Status{Code: SigningCredentialTrusted})}, Trusted},
		{"informational only", Result{ActiveManifest: append(slices.Clone(ok), Status{Code: TimeStampUntrusted})}, Valid},
		{"failure", Result{ActiveManifest: append(slices.Clone(ok), Status{Code: AssertionDataHashMismatch})}, Invalid},
		{"no signature check", Result{ActiveManifest: []Status{{Code: ClaimSignatureValidated}}}, Invalid},
		{"failing delta", Result{ActiveManifest: append(slices.Clone(ok), Status{Code: SigningCredentialTrusted}),
			IngredientDeltas: []IngredientDelta{{ValidationDeltas: []Status{{Code: IngredientManifestMismatch}}}}}, Invalid},
		{"untrusted delta", Result{ActiveManifest: append(slices.Clone(ok), Status{Code: SigningCredentialTrusted}),
			IngredientDeltas: []IngredientDelta{{ValidationDeltas: []Status{{Code: SigningCredentialUntrusted}}}}}, Valid},
	}
	for _, tt := range tests {
		if got := tt.r.State(); got != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, got, tt.want)
		}
	}
}

// TestFileMutations runs File on thousands of randomly corrupted fixtures
// (fixed seed, so failures reproduce): every run must return statuses,
// never panic, and finish within a deadline.
func TestFileMutations(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	r := mrand.New(mrand.NewPCG(7, 9))
	n := 1500
	if testing.Short() {
		n = 200
	}
	for _, name := range []string{"signed/small.jpg", "signed/small.png", "signed/edited.jpg", "signed/titled-ts.jpg"} {
		seed, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			b := slices.Clone(seed)
			for range 1 + r.IntN(4) {
				p := r.IntN(len(b))
				switch r.IntN(4) {
				case 0:
					b[p] ^= byte(1 << r.IntN(8))
				case 1:
					b[p] = byte(r.IntN(256))
				case 2:
					b[p] = 0xFF
				default:
					b = b[:p] // truncate
				}
				if len(b) == 0 {
					break
				}
			}
			done := make(chan *Result, 1)
			go func() { done <- File(b, nil) }()
			select {
			case res := <-done:
				if len(res.ActiveManifest) == 0 {
					t.Fatalf("%s mutation %d: no statuses", name, i)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s mutation %d: File did not finish in 5s", name, i)
			}
		}
	}
}

// FuzzFile checks that verification never panics, whatever the input.
// Note: on Windows the Go fuzzing engine's throughput collapses for this
// target (tens of execs per second); TestFileMutations is the routine check.
func FuzzFile(f *testing.F) {
	dir, err := fixtures.Dir()
	if err == nil {
		for _, name := range []string{"signed/small.jpg", "signed/small.png", "signed/edited.jpg", "broken/sig-flip.jpg"} {
			if b, err := os.ReadFile(dir + "/" + name); err == nil {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := File(b, nil)
		if len(r.ActiveManifest) == 0 {
			t.Fatal("no statuses")
		}
		_ = r.State()
	})
}
