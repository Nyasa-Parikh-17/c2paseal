package sign

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/fxamacker/cbor/v2"
	gocose "github.com/veraison/go-cose"
)

// JUMBF content types (C2PA 2.4 §11.1).
var (
	uuidStore      = c2paUUID(0x63327061) // "c2pa"
	uuidManifest   = c2paUUID(0x63326D61) // "c2ma"
	uuidAssertions = c2paUUID(0x63326173) // "c2as"
	uuidClaim      = c2paUUID(0x6332636C) // "c2cl"
	uuidSignature  = c2paUUID(0x63326373) // "c2cs"
	uuidCBOR       = c2paUUID(0x63626F72) // "cbor"
	uuidEmbedded   = jumbf.UUID{0x40, 0xCB, 0x0C, 0x32, 0xBB, 0x8A, 0x48, 0x9D, 0xA7, 0x0B, 0x2A, 0xD6, 0xF4, 0x7F, 0x43, 0x69}
)

// c2paUUID returns <prefix>-0011-0010-8000-00AA00389B71.
func c2paUUID(prefix uint32) jumbf.UUID {
	return jumbf.UUID{byte(prefix >> 24), byte(prefix >> 16), byte(prefix >> 8), byte(prefix),
		0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}
}

const (
	esSignatureLen = 64 // ES256 raw r|s
	saltLen        = 16
	labelHashData  = assertion.LabelDataHash
	labelActions   = assertion.LabelActionsV2
	labelThumbnail = assertion.LabelThumbnailClaim
)

// ErrSizeMismatch means a backfilled value did not have the size of its
// placeholder. The reserve-and-backfill scheme relies on every value keeping
// its size, so this is always an error, never patched over.
var ErrSizeMismatch = errors.New("sign: backfilled value differs in size from its placeholder")

// Manifest is a manifest store under construction: a complete JUMBF tree
// whose hard-binding values and signature start as zero-filled placeholders
// of their final size and are then filled in (SetBinding, Seal).
type Manifest struct {
	Label string
	Claim *manifest.Claim
	Store *jumbf.Box // the whole manifest store superbox

	opts     *Options
	hashData *jumbf.Box // cbor content box of c2pa.hash.data
	hashSup  *jumbf.Box // the c2pa.hash.data assertion superbox
	claim    *jumbf.Box // cbor content box of the claim
	sig      *jumbf.Box // cbor content box of the signature
	layout   hashDataLayout

	protected []byte // serialised COSE protected header
	sigLen    int    // placeholder signature length (esSignatureLen)
	binding   [2]uint64
	digest    []byte
}

// buildConfig exists so tests can build a deliberately wrong placeholder.
type buildConfig struct {
	sigLen int
}

// Build builds an unsigned manifest store: assertions (actions, optional
// thumbnail, hard binding), claim and COSE signature, with zeroed binding
// values and a zeroed signature at their final sizes.
func Build(opts *Options) (*Manifest, error) {
	return build(opts, buildConfig{sigLen: esSignatureLen})
}

func build(opts *Options, cfg buildConfig) (*Manifest, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	r := opts.rand()
	id, err := newUUID(r)
	if err != nil {
		return nil, err
	}
	iid, err := newUUID(r)
	if err != nil {
		return nil, err
	}
	m := &Manifest{Label: "urn:c2pa:" + id, opts: opts, sigLen: cfg.sigLen, digest: make([]byte, digestLen)}

	// Assertions.
	actionsCBOR, err := cbormode.Enc.Marshal(&assertion.Actions{Actions: opts.actions()})
	if err != nil {
		return nil, fmt.Errorf("sign: encode actions: %w", err)
	}
	actionsSup, err := assertionBox(r, labelActions, uuidCBOR, &jumbf.Box{Type: "cbor", Payload: actionsCBOR})
	if err != nil {
		return nil, err
	}
	hd, layout := encodeHashData(0, 0, nil)
	m.layout = layout
	m.hashData = &jumbf.Box{Type: "cbor", Payload: hd}
	if m.hashSup, err = assertionBox(r, labelHashData, uuidCBOR, m.hashData); err != nil {
		return nil, err
	}
	created := []*jumbf.Box{actionsSup, m.hashSup}
	var gathered []*jumbf.Box
	if t := opts.Thumbnail; t != nil {
		thumb, err := assertionBox(r, labelThumbnail, uuidEmbedded,
			&jumbf.Box{Type: "bfdb", Payload: append(append([]byte{0}, t.Format...), 0)},
			&jumbf.Box{Type: "bidb", Payload: t.Data})
		if err != nil {
			return nil, err
		}
		gathered = append(gathered, thumb)
	}

	// Claim.
	name, version := opts.generator()
	m.Claim = &manifest.Claim{
		InstanceID:         "xmp:iid:" + iid,
		ClaimGeneratorInfo: manifest.GeneratorInfo{"name": name, "version": version},
		Signature:          manifest.JUMBFURIPrefix + "/" + manifest.LabelStore + "/" + m.Label + "/" + manifest.LabelSignature,
		Title:              opts.Title,
		Alg:                manifest.DefaultAlg,
	}
	for _, b := range created {
		ref, err := hashedURI(b)
		if err != nil {
			return nil, err
		}
		m.Claim.CreatedAssertions = append(m.Claim.CreatedAssertions, ref)
	}
	for _, b := range gathered {
		ref, err := hashedURI(b)
		if err != nil {
			return nil, err
		}
		m.Claim.GatheredAssertions = append(m.Claim.GatheredAssertions, ref)
	}
	claimCBOR, err := m.Claim.Encode()
	if err != nil {
		return nil, fmt.Errorf("sign: encode claim: %w", err)
	}
	m.Claim.Raw = claimCBOR
	m.claim = &jumbf.Box{Type: "cbor", Payload: claimCBOR}

	// Signature placeholder.
	if m.protected, err = protectedHeader(opts); err != nil {
		return nil, err
	}
	sigCBOR, err := m.coseSign1(make([]byte, m.sigLen))
	if err != nil {
		return nil, err
	}
	m.sig = &jumbf.Box{Type: "cbor", Payload: sigCBOR}

	assertions := superbox(uuidAssertions, manifest.LabelAssertions, append(created, gathered...)...)
	man := superbox(uuidManifest, m.Label,
		assertions,
		superbox(uuidClaim, manifest.LabelClaimV2, m.claim),
		superbox(uuidSignature, manifest.LabelSignature, m.sig))
	m.Store = superbox(uuidStore, manifest.LabelStore, man)
	return m, nil
}

// Bytes serialises the manifest store.
func (m *Manifest) Bytes() []byte { return jumbf.Serialize(m.Store) }

// patch is a byte range of the serialised store that changed.
type patch struct {
	off  int
	data []byte
}

// replacePayload swaps a content box's payload for one of the same length
// and returns where the new bytes go in the serialised store.
func (m *Manifest) replacePayload(box *jumbf.Box, payload []byte) (patch, error) {
	if len(payload) != len(box.Payload) {
		return patch{}, fmt.Errorf("%w: %s payload %d bytes, placeholder %d", ErrSizeMismatch, box.Type, len(payload), len(box.Payload))
	}
	off, ok := offsetOf(m.Store, box, 0)
	if !ok {
		return patch{}, errors.New("sign: box not in store")
	}
	box.Payload = payload
	return patch{off: off + box.HeaderLen(), data: payload}, nil
}

// SetExclusion fills in the hard-binding exclusion (step 4).
func (m *Manifest) SetExclusion(start, length uint64) (patch, error) {
	m.binding = [2]uint64{start, length}
	b, _ := encodeHashData(start, length, m.digest)
	return m.replacePayload(m.hashData, b)
}

// SetDigest fills in the hard-binding hash (step 5).
func (m *Manifest) SetDigest(digest []byte) (patch, error) {
	if len(digest) != digestLen {
		return patch{}, fmt.Errorf("%w: digest %d bytes, want %d", ErrSizeMismatch, len(digest), digestLen)
	}
	m.digest = digest
	b, _ := encodeHashData(m.binding[0], m.binding[1], digest)
	return m.replacePayload(m.hashData, b)
}

// Seal re-hashes the hard-binding assertion, updates its hashed URI in the
// claim and signs the claim (step 6). It returns the claim and signature
// patches.
func (m *Manifest) Seal() ([]patch, error) {
	ref, err := hashedURI(m.hashSup)
	if err != nil {
		return nil, err
	}
	found := false
	for i := range m.Claim.CreatedAssertions {
		if m.Claim.CreatedAssertions[i].URL == ref.URL {
			m.Claim.CreatedAssertions[i] = ref
			found = true
		}
	}
	if !found {
		return nil, errors.New("sign: claim does not reference c2pa.hash.data")
	}
	claimCBOR, err := m.Claim.Encode()
	if err != nil {
		return nil, fmt.Errorf("sign: encode claim: %w", err)
	}
	claimPatch, err := m.replacePayload(m.claim, claimCBOR)
	if err != nil {
		return nil, err
	}
	m.Claim.Raw = claimCBOR

	sig, err := m.signClaim(claimCBOR)
	if err != nil {
		return nil, err
	}
	sigCBOR, err := m.coseSign1(sig)
	if err != nil {
		return nil, err
	}
	sigPatch, err := m.replacePayload(m.sig, sigCBOR)
	if err != nil {
		return nil, err
	}
	return []patch{claimPatch, sigPatch}, nil
}

// signClaim signs the COSE Sig_structure over the claim bytes with ES256.
func (m *Manifest) signClaim(claim []byte) ([]byte, error) {
	signer, err := gocose.NewSigner(gocose.AlgorithmES256, m.opts.Signer)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	tbs, err := cbormode.Enc.Marshal([]any{"Signature1", m.protected, []byte{}, claim})
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, tbs)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig, nil
}

// coseSign1 encodes the tagged COSE_Sign1 with a detached payload.
func (m *Manifest) coseSign1(sig []byte) ([]byte, error) {
	return cbormode.Enc.Marshal(cbor.Tag{Number: 18, Content: []any{m.protected, map[any]any{}, nil, sig}})
}

// protectedHeader encodes {alg: ES256, x5chain: chain}.
func protectedHeader(opts *Options) ([]byte, error) {
	var chain any = opts.Chain[0].Raw
	if len(opts.Chain) > 1 {
		ders := make([]any, len(opts.Chain))
		for i, c := range opts.Chain {
			ders[i] = c.Raw
		}
		chain = ders
	}
	return cbormode.Enc.Marshal(map[int]any{1: -7, 33: chain})
}

// hashedURI references an assertion superbox by relative URI and hash.
func hashedURI(b *jumbf.Box) (manifest.HashedURI, error) {
	sum, err := manifest.HashBox(manifest.DefaultAlg, b)
	if err != nil {
		return manifest.HashedURI{}, err
	}
	return manifest.HashedURI{URL: manifest.JUMBFURIPrefix + manifest.LabelAssertions + "/" + b.Label(), Hash: sum}, nil
}

// superbox builds a jumb box with a requestable, labelled description.
func superbox(ct jumbf.UUID, label string, children ...*jumbf.Box) *jumbf.Box {
	desc := &jumbf.Box{Type: jumbf.TypeDescription, Description: &jumbf.Description{
		ContentType: ct, Toggles: jumbf.ToggleRequestable | jumbf.ToggleLabel, Label: label}}
	return &jumbf.Box{Type: jumbf.TypeSuperbox, Children: append([]*jumbf.Box{desc}, children...)}
}

// assertionBox builds an assertion superbox whose description carries a
// random c2sh salt box, as c2pa-rs does.
func assertionBox(r io.Reader, label string, ct jumbf.UUID, content ...*jumbf.Box) (*jumbf.Box, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("sign: salt: %w", err)
	}
	b := superbox(ct, label, content...)
	d := b.Children[0].Description
	d.Toggles |= jumbf.TogglePrivate
	d.Private = &jumbf.Box{Type: "c2sh", Payload: salt}
	return b, nil
}

// offsetOf returns where box starts in the serialisation of root, which
// starts at off.
func offsetOf(root, box *jumbf.Box, off int) (int, bool) {
	if root == box {
		return off, true
	}
	if !root.IsSuperbox() {
		return 0, false
	}
	off += root.HeaderLen()
	for _, c := range root.Children {
		if o, ok := offsetOf(c, box, off); ok {
			return o, true
		}
		off += c.Size()
	}
	return 0, false
}

// newUUID returns a random (version 4) UUID string.
func newUUID(r io.Reader) (string, error) {
	var u [16]byte
	if _, err := io.ReadFull(r, u[:]); err != nil {
		return "", fmt.Errorf("sign: uuid: %w", err)
	}
	u[6] = u[6]&0x0F | 0x40
	u[8] = u[8]&0x3F | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
}
