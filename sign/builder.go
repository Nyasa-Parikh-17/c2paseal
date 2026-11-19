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

	external  bool        // store kept outside the file: hash.data has no exclusion
	bmff      bool        // ISO BMFF file: the hard binding is c2pa.hash.bmff.v3
	protected []byte      // serialised COSE protected header
	sigLen    int         // placeholder signature length (esSignatureLen)
	tstSize   int         // reserved unprotected header size; 0 = no time-stamp
	extra     map[any]any // other unprotected header entries (rVals)
	binding   [2]uint64
	digest    []byte
}

// buildConfig exists so tests can build a deliberately wrong placeholder.
type buildConfig struct {
	sigLen int
	bmff   bool // hard binding c2pa.hash.bmff.v3 instead of c2pa.hash.data
}

// Build builds an unsigned manifest store: assertions (actions, optional
// thumbnail, hard binding), claim and COSE signature, with zeroed binding
// values and a zeroed signature at their final sizes.
func Build(opts *Options) (*Manifest, error) {
	return build(opts, buildConfig{sigLen: esSignatureLen}, nil)
}

// build builds the placeholder manifest. With a parent, the new store holds
// the parent's manifests unchanged, then the new one, which records the
// parent as a c2pa.ingredient.v3 assertion referenced by c2pa.opened.
//
// The steps draw salts and UUIDs from opts' randomness in a fixed order
// (manifest ID, instance ID, then each assertion in claim order), so a fixed
// Options.Rand gives the same bytes every time.
func build(opts *Options, cfg buildConfig, p *parent) (*Manifest, error) {
	if opts == nil {
		return nil, ErrNoSigner
	}
	if err := opts.validate(p != nil); err != nil {
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
	m := &Manifest{Label: "urn:c2pa:" + id, opts: opts, sigLen: cfg.sigLen, digest: make([]byte, digestLen), external: opts.Sidecar, bmff: cfg.bmff}

	created, gathered, err := m.buildAssertions(r, p)
	if err != nil {
		return nil, err
	}
	if err := m.buildClaim(iid, created, gathered); err != nil {
		return nil, err
	}
	if err := m.buildSignature(); err != nil {
		return nil, err
	}

	assertions := superbox(uuidAssertions, manifest.LabelAssertions, append(created, gathered...)...)
	man := superbox(uuidManifest, m.Label,
		assertions,
		superbox(uuidClaim, manifest.LabelClaimV2, m.claim),
		superbox(uuidSignature, manifest.LabelSignature, m.sig))
	var manifests []*jumbf.Box
	if p != nil {
		manifests = append(manifests, p.manifests...)
	}
	m.Store = superbox(uuidStore, manifest.LabelStore, append(manifests, man)...)
	return m, nil
}

// buildAssertions builds the assertion boxes in claim order: the created
// ones (the parent ingredient if any, since c2pa.opened refers to it; the
// actions; the hard binding, kept in m for backfilling; the soft bindings)
// and the gathered ones (the thumbnail).
func (m *Manifest) buildAssertions(r io.Reader, p *parent) (created, gathered []*jumbf.Box, err error) {
	opts := m.opts
	acts := opts.actions(p != nil)
	if p != nil {
		ing, ref, err := parentIngredient(r, p)
		if err != nil {
			return nil, nil, err
		}
		acts = withIngredient(acts, ref)
		created = append(created, ing)
	}
	actionsCBOR, err := cbormode.Enc.Marshal(&assertion.Actions{Actions: acts})
	if err != nil {
		return nil, nil, fmt.Errorf("sign: encode actions: %w", err)
	}
	actionsSup, err := assertionBox(r, labelActions, uuidCBOR, &jumbf.Box{Type: "cbor", Payload: actionsCBOR})
	if err != nil {
		return nil, nil, err
	}

	hd, layout := m.encodeHashData(0, 0, nil)
	m.layout = layout
	m.hashData = &jumbf.Box{Type: "cbor", Payload: hd}
	bindingLabel := labelHashData
	if m.bmff {
		bindingLabel = assertion.LabelBMFFHashV3
	}
	if m.hashSup, err = assertionBox(r, bindingLabel, uuidCBOR, m.hashData); err != nil {
		return nil, nil, err
	}
	created = append(created, actionsSup, m.hashSup)

	soft, err := softBindingBoxes(r, opts.SoftBindings)
	if err != nil {
		return nil, nil, err
	}
	created = append(created, soft...)

	if t := opts.Thumbnail; t != nil {
		thumb, err := assertionBox(r, labelThumbnail, uuidEmbedded,
			&jumbf.Box{Type: "bfdb", Payload: append(append([]byte{0}, t.Format...), 0)},
			&jumbf.Box{Type: "bidb", Payload: t.Data})
		if err != nil {
			return nil, nil, err
		}
		gathered = append(gathered, thumb)
	}
	return created, gathered, nil
}

// parentIngredient builds the c2pa.ingredient.v3 assertion for the parent
// and the hashed URI that c2pa.opened uses to reference it.
func parentIngredient(r io.Reader, p *parent) (*jumbf.Box, manifest.HashedURI, error) {
	ingCBOR, err := p.ingredientCBOR()
	if err != nil {
		return nil, manifest.HashedURI{}, fmt.Errorf("sign: encode ingredient: %w", err)
	}
	ing, err := assertionBox(r, LabelIngredient, uuidCBOR, &jumbf.Box{Type: "cbor", Payload: ingCBOR})
	if err != nil {
		return nil, manifest.HashedURI{}, err
	}
	ref, err := hashedURI(ing)
	if err != nil {
		return nil, manifest.HashedURI{}, err
	}
	return ing, ref, nil
}

// withIngredient returns a copy of acts whose first action (c2pa.opened)
// lists ref as its ingredient. acts and its parameters are not modified.
func withIngredient(acts []assertion.Action, ref manifest.HashedURI) []assertion.Action {
	params := map[string]any{}
	for k, v := range acts[0].Parameters {
		params[k] = v
	}
	params["ingredients"] = []any{ref}
	acts = append([]assertion.Action(nil), acts...)
	acts[0].Parameters = params
	return acts
}

// softBindingBoxes builds one c2pa.soft-binding assertion per soft binding;
// the second and later get the label instance suffixes __1, __2, ...
func softBindingBoxes(r io.Reader, sbs []SoftBinding) ([]*jumbf.Box, error) {
	var out []*jumbf.Box
	for i, sb := range sbs {
		sbCBOR, err := cbormode.Enc.Marshal(&assertion.SoftBinding{
			Alg:    sb.Alg,
			Blocks: []assertion.SoftBindingBlock{{Value: sb.Value}},
			Pad:    []byte{},
		})
		if err != nil {
			return nil, fmt.Errorf("sign: encode soft binding: %w", err)
		}
		label := assertion.LabelSoftBinding
		if i > 0 {
			label = fmt.Sprintf("%s__%d", label, i)
		}
		sup, err := assertionBox(r, label, uuidCBOR, &jumbf.Box{Type: "cbor", Payload: sbCBOR})
		if err != nil {
			return nil, err
		}
		out = append(out, sup)
	}
	return out, nil
}

// buildClaim builds and encodes the v2 claim, referencing the created and
// gathered assertions by hashed URI.
func (m *Manifest) buildClaim(iid string, created, gathered []*jumbf.Box) error {
	name, version := m.opts.generator()
	m.Claim = &manifest.Claim{
		InstanceID:         "xmp:iid:" + iid,
		ClaimGeneratorInfo: manifest.GeneratorInfo{"name": name, "version": version},
		Signature:          manifest.JUMBFURIPrefix + "/" + manifest.LabelStore + "/" + m.Label + "/" + manifest.LabelSignature,
		Title:              m.opts.Title,
		Alg:                manifest.DefaultAlg,
	}
	for _, b := range created {
		ref, err := hashedURI(b)
		if err != nil {
			return err
		}
		m.Claim.CreatedAssertions = append(m.Claim.CreatedAssertions, ref)
	}
	for _, b := range gathered {
		ref, err := hashedURI(b)
		if err != nil {
			return err
		}
		m.Claim.GatheredAssertions = append(m.Claim.GatheredAssertions, ref)
	}
	claimCBOR, err := m.Claim.Encode()
	if err != nil {
		return fmt.Errorf("sign: encode claim: %w", err)
	}
	m.Claim.Raw = claimCBOR
	m.claim = &jumbf.Box{Type: "cbor", Payload: claimCBOR}
	return nil
}

// buildSignature builds the COSE_Sign1 placeholder at its final size: the
// protected header, a stapled OCSP response if any, room for the time-stamp
// token, and a zeroed signature.
func (m *Manifest) buildSignature() error {
	var err error
	if m.protected, err = protectedHeader(m.opts); err != nil {
		return err
	}
	ocspDER, err := m.opts.staple()
	if err != nil {
		return err
	}
	if ocspDER != nil {
		m.extra = map[any]any{"rVals": rValsHeader(ocspDER)}
	}
	if m.opts.TSAURL != "" {
		if m.tstSize, err = tstHeaderSize(m.opts.timestampReserve(), m.extra); err != nil {
			return err
		}
	}
	sigCBOR, err := m.coseSign1(make([]byte, m.sigLen), nil)
	if err != nil {
		return err
	}
	m.sig = &jumbf.Box{Type: "cbor", Payload: sigCBOR}
	return nil
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
	if m.bmff {
		return patch{}, errors.New("sign: c2pa.hash.bmff exclusions name boxes; there is no range to set")
	}
	if m.external {
		return patch{}, errors.New("sign: a manifest kept outside the file has no exclusion")
	}
	m.binding = [2]uint64{start, length}
	b, _ := m.encodeHashData(start, length, m.digest)
	return m.replacePayload(m.hashData, b)
}

// SetDigest fills in the hard-binding hash (step 5).
func (m *Manifest) SetDigest(digest []byte) (patch, error) {
	if len(digest) != digestLen {
		return patch{}, fmt.Errorf("%w: digest %d bytes, want %d", ErrSizeMismatch, len(digest), digestLen)
	}
	m.digest = digest
	b, _ := m.encodeHashData(m.binding[0], m.binding[1], digest)
	return m.replacePayload(m.hashData, b)
}

// Seal re-hashes the hard-binding assertion, updates its hashed URI in the
// claim and signs the claim (step 6). With Options.TSAURL set it then
// time-stamps the signature, which needs the network. It returns the claim
// and signature patches.
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
		return nil, errors.New("sign: claim does not reference the hard-binding assertion")
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
	var token []byte
	if m.tstSize > 0 {
		data, err := m.counterSignatureData(sig)
		if err != nil {
			return nil, fmt.Errorf("sign: encode countersignature data: %w", err)
		}
		if token, err = m.opts.fetchTimestamp(data); err != nil {
			return nil, err
		}
	}
	sigCBOR, err := m.coseSign1(sig, token)
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

// coseSign1 encodes the tagged COSE_Sign1 with a detached payload. With a
// time-stamp slot reserved, the unprotected header always encodes to
// m.tstSize bytes, whatever the token (nil for the placeholder).
func (m *Manifest) coseSign1(sig, token []byte) ([]byte, error) {
	unprotected, err := tstHeader(token, m.tstSize, m.extra)
	if err != nil {
		return nil, err
	}
	return cbormode.Enc.Marshal(cbor.Tag{Number: 18, Content: []any{m.protected, unprotected, nil, sig}})
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
