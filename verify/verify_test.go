package verify

import (
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
	t.Helper()
	root, rootKey := ca(t)
	key := newKey(t)
	cert := create(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "Test TSA", Organization: []string{"Test"}},
		NotBefore:   t0.AddDate(-1, 0, 0),
		NotAfter:    t0.AddDate(3, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}, root, &key.PublicKey, rootKey)
	return cert, key
}

// token makes an RFC 3161 token over data's SHA-256 at time at.
func token(t *testing.T, data []byte, at time.Time) []byte {
	t.Helper()
	cert, key := tsa(t)
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

// stamped signs claimBytes like signedManifest and adds a sigTst2 header
// holding the given tokens, plus (if overRealData) one made over the real
// countersignature data.
func stamped(t *testing.T, leaf *x509.Certificate, key crypto.Signer, at time.Time, tokens [][]byte, overRealData bool) *manifest.Manifest {
	t.Helper()
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
		sigBstr, _ := cbormode.Enc.Marshal(msg.Signature)
		tbs, _ := cbormode.Enc.Marshal([]any{"CounterSignature", raw, []byte{}, sigBstr})
		tokens = append(tokens, token(t, tbs, at))
	}
	var list []any
	for _, tok := range tokens {
		list = append(list, map[string]any{"val": tok})
	}
	msg.Headers.Unprotected["sigTst2"] = map[string]any{"tstTokens": list}
	b, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	s, err := cose.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	const label = "urn:c2pa:3fa85f64-5717-4562-b3fc-2c963f66afa6"
	return &manifest.Manifest{
		Label:     label,
		Claim:     &manifest.Claim{Signature: "self#jumbf=/c2pa/" + label + "/c2pa.signature", Raw: claimBytes},
		Signature: s,
	}
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
	}
	for _, tt := range tests {
		if got := codes(checkClaim(tt.m, tt.opts)); !slices.Equal(got, tt.want) {
			t.Errorf("%s:\n got  %q\n want %q", tt.name, got, tt.want)
		}
	}
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
