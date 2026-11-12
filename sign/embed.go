package sign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
)

// Signed is the result of Asset.
type Signed struct {
	// File is the signed asset.
	File []byte
	// Store is its manifest store: the bytes embedded in File, or, with
	// Options.Sidecar, the store to save as a .c2pa sidecar or to serve at
	// Options.RemoteURL.
	Store []byte
	// Parent reports whether an existing manifest store was recorded as
	// the parent ingredient.
	Parent bool
}

// ErrFormat is returned by Asset for a file that is neither JPEG nor PNG.
var ErrFormat = errors.New("sign: signing supports JPEG and PNG only")

// ErrSidecar is returned by JPEG and PNG when Options.Sidecar is set: they
// return only the file, so the store would be lost. Use Asset.
var ErrSidecar = errors.New("sign: Options.Sidecar needs Asset, which returns the manifest store")

// Asset signs a JPEG or PNG and returns the signed file and its manifest
// store. in is not modified. See embed for the steps.
//
// If in already has a manifest store, its manifests are kept, unchanged,
// in the new store, and the new manifest records the old active manifest
// as its parent ingredient (c2pa.ingredient.v3, relationship parentOf),
// with a c2pa.opened action. Options.NoHistory replaces the old store
// instead.
func Asset(in []byte, opts *Options) (*Signed, error) {
	switch asset.Detect(in) {
	case asset.JPEG:
		return embed(in, opts, buildConfig{sigLen: esSignatureLen}, &jpegContainer{})
	case asset.PNG:
		return embed(in, opts, buildConfig{sigLen: esSignatureLen}, &pngContainer{})
	}
	return nil, ErrFormat
}

// JPEG signs a JPEG: it embeds a new C2PA manifest store in APP11 segments,
// bound to the image with c2pa.hash.data, and returns the signed file. An
// existing store becomes the parent ingredient, as for Asset.
func JPEG(in []byte, opts *Options) ([]byte, error) {
	if opts != nil && opts.Sidecar {
		return nil, ErrSidecar
	}
	return fileOnly(embed(in, opts, buildConfig{sigLen: esSignatureLen}, &jpegContainer{}))
}

// PNG signs a PNG: like JPEG, with the store in one caBX chunk straight
// after IHDR. The hard-binding exclusion covers the whole chunk (length,
// type, data and CRC), as c2pa-rs writes it, so the CRC, which is computed
// last, after every backfilled value is in place, is outside the hash.
func PNG(in []byte, opts *Options) ([]byte, error) {
	if opts != nil && opts.Sidecar {
		return nil, ErrSidecar
	}
	return fileOnly(embed(in, opts, buildConfig{sigLen: esSignatureLen}, &pngContainer{}))
}

func fileOnly(s *Signed, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return s.File, nil
}

// container is the format-specific part of embedding a manifest store.
type container interface {
	// strip removes any existing manifest store.
	strip(in []byte) ([]byte, error)
	// insert inserts the placeholder store and returns the file and the
	// hard-binding exclusion range covering everything it inserted.
	insert(stripped, store []byte, hdrLen int) (file []byte, start, length int, err error)
	// write overwrites store bytes in place at store offset off.
	write(file []byte, off int, data []byte) error
	// finish runs after all writes (PNG: recompute the chunk CRC).
	finish(file []byte) error
	// extract reads the store back from the signed file.
	extract(file []byte) ([]byte, error)
}

// embed signs in with reserve-and-backfill, in exactly this order:
//
//  0. read the existing store, if any, as the parent; strip it from the
//     file; write Options.RemoteURL into the XMP;
//  1. build the manifest with zero-filled placeholders of final size: the
//     hash.data digest, its exclusion values and the ES256 signature (and
//     the time-stamp slot, if Options.TSAURL is set);
//  2. serialise the store and record its length;
//  3. insert it into the stripped file (JPEG: APP11 segments, closed-form
//     count; PNG: one caBX chunk);
//  4. write the now-known exclusion range in place;
//  5. hash the file with the exclusion skipped and write the digest in place;
//  6. re-hash the hash.data assertion, update its hashed URI in the claim,
//     sign the claim, time-stamp the signature if Options.TSAURL is set
//     (into the slot reserved in step 1) and write claim and signature in place;
//  7. check that the final store has the placeholder's length (and bytes).
//
// With Options.Sidecar, steps 3 and 4 are skipped: nothing is inserted, and
// the hash in step 5 covers the whole file.
func embed(in []byte, opts *Options, cfg buildConfig, c container) (*Signed, error) {
	if err := opts.validateSigner(); err != nil {
		return nil, err
	}
	// 0. Parent, stripped file, remote reference.
	par, err := readParent(in, opts)
	if err != nil {
		return nil, err
	}
	if err := opts.validate(par != nil); err != nil {
		return nil, err
	}
	stripped, err := c.strip(in)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if opts.RemoteURL != "" {
		if stripped, err = asset.SetRemoteURL(stripped, opts.RemoteURL); err != nil {
			return nil, fmt.Errorf("sign: remote manifest reference: %w", err)
		}
	}

	// 1. Placeholder manifest.
	m, err := build(opts, cfg, par)
	if err != nil {
		return nil, err
	}

	// 2. Serialise; this length is fixed from here on.
	store := m.Bytes()
	reserved := len(store)

	if opts.Sidecar {
		return external(m, stripped, store, reserved, par != nil)
	}

	// 3. Insert the placeholder store.
	file, start, length, err := c.insert(stripped, store, m.Store.HeaderLen())
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Every backfilled value is written into the file in place and mirrored
	// into the store bytes, which step 7 checks.
	write := func(p patch) error {
		copy(store[p.off:], p.data)
		if err := c.write(file, p.off, p.data); err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		return nil
	}

	// 4. Exclusion: everything the container inserted.
	p, err := m.SetExclusion(uint64(start), uint64(length))
	if err != nil {
		return nil, err
	}
	if err := write(p); err != nil {
		return nil, err
	}

	// 5. Hard-binding digest over everything outside the exclusion.
	h := sha256.New()
	h.Write(file[:start])
	h.Write(file[start+length:])
	if p, err = m.SetDigest(h.Sum(nil)); err != nil {
		return nil, err
	}
	if err := write(p); err != nil {
		return nil, err
	}

	// 6. Claim and signature.
	patches, err := m.Seal()
	if err != nil {
		return nil, err
	}
	for _, p := range patches {
		if err := write(p); err != nil {
			return nil, err
		}
	}
	if err := c.finish(file); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// 7. The final store must be exactly the reserved size, and the bytes
	// written in place must be what serialising the final tree gives.
	final := m.Bytes()
	if err := checkReserved(reserved, len(final)); err != nil {
		return nil, err
	}
	if !bytes.Equal(final, store) {
		return nil, errors.New("sign: in-place writes do not match the final manifest store")
	}
	got, err := c.extract(file)
	if err != nil || !bytes.Equal(got, final) {
		return nil, fmt.Errorf("sign: signed file does not carry the final manifest store: %v", err)
	}
	return &Signed{File: file, Store: final, Parent: par != nil}, nil
}

// external finishes a manifest kept outside the file: the hard binding
// hashes the whole file, then the claim is signed. The size check still
// applies, since the store's offsets were fixed when it was serialised.
func external(m *Manifest, file, store []byte, reserved int, hasParent bool) (*Signed, error) {
	sum := sha256.Sum256(file)
	p, err := m.SetDigest(sum[:])
	if err != nil {
		return nil, err
	}
	patches, err := m.Seal()
	if err != nil {
		return nil, err
	}
	for _, p := range append([]patch{p}, patches...) {
		copy(store[p.off:], p.data)
	}
	final := m.Bytes()
	if err := checkReserved(reserved, len(final)); err != nil {
		return nil, err
	}
	if !bytes.Equal(final, store) {
		return nil, errors.New("sign: in-place writes do not match the final manifest store")
	}
	return &Signed{File: file, Store: final, Parent: hasParent}, nil
}

// checkReserved enforces the reserve-and-backfill invariant: the final
// manifest store must have exactly the placeholder's length, or every offset
// already written into the file (and the hard-binding exclusion) is wrong.
func checkReserved(placeholderLen, finalLen int) error {
	if placeholderLen != finalLen {
		return fmt.Errorf("%w: manifest store is %d bytes, placeholder was %d", ErrSizeMismatch, finalLen, placeholderLen)
	}
	return nil
}

// jpegContainer embeds the store in APP11 segments.
type jpegContainer struct {
	segs   []jpeg.Segment
	hdrLen int
}

func (j *jpegContainer) strip(in []byte) ([]byte, error) { return jpeg.Strip(in) }

func (j *jpegContainer) insert(stripped, store []byte, hdrLen int) ([]byte, int, int, error) {
	want := jpeg.SegmentCount(len(store))
	file, segs, err := jpeg.Insert(stripped, store)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(segs) != want {
		return nil, 0, 0, fmt.Errorf("inserted %d APP11 segments, expected %d", len(segs), want)
	}
	start := segs[0].Offset
	length := jpeg.InsertedSize(len(store), hdrLen)
	if segs[len(segs)-1].End()-start != length {
		return nil, 0, 0, errors.New("APP11 segments are not contiguous")
	}
	j.segs, j.hdrLen = segs, hdrLen
	return file, start, length, nil
}

func (j *jpegContainer) write(file []byte, off int, data []byte) error {
	return jpeg.WriteStore(file, j.segs, j.hdrLen, off, data)
}

func (j *jpegContainer) finish([]byte) error { return nil }

func (j *jpegContainer) extract(file []byte) ([]byte, error) {
	st, err := jpeg.Extract(file)
	if err != nil {
		return nil, err
	}
	return st.JUMBF, nil
}

// pngContainer embeds the store in one caBX chunk.
type pngContainer struct {
	chunk png.Chunk
}

func (p *pngContainer) strip(in []byte) ([]byte, error) { return png.Strip(in) }

func (p *pngContainer) insert(stripped, store []byte, _ int) ([]byte, int, int, error) {
	file, c, err := png.Insert(stripped, store)
	if err != nil {
		return nil, 0, 0, err
	}
	if c.Size() != png.InsertedSize(len(store)) || c.End() > len(file) {
		return nil, 0, 0, errors.New("caBX chunk does not have the expected size")
	}
	p.chunk = c
	return file, c.Offset, c.Size(), nil
}

func (p *pngContainer) write(file []byte, off int, data []byte) error {
	return png.WriteStore(file, p.chunk, off, data)
}

func (p *pngContainer) finish(file []byte) error { return png.UpdateCRC(file, p.chunk) }

func (p *pngContainer) extract(file []byte) ([]byte, error) {
	chunks, err := png.Chunks(file)
	if err != nil {
		return nil, err
	}
	for _, c := range chunks {
		if c.Type == png.TypeC2PA && !c.CRCValid {
			return nil, errors.New("caBX chunk CRC is wrong")
		}
	}
	st, err := png.Extract(file)
	if err != nil {
		return nil, err
	}
	return st.JUMBF, nil
}
