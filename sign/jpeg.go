package sign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
)

// JPEG signs a JPEG: it embeds a new C2PA manifest store bound to the image
// with c2pa.hash.data, replacing any existing store, and returns the signed
// file. in is not modified.
//
// It uses reserve-and-backfill, in exactly this order:
//
//  1. build the manifest with zero-filled placeholders of final size: the
//     hash.data digest, its exclusion values and the ES256 signature;
//  2. serialise the store and record its length;
//  3. insert it into the stripped JPEG as APP11 segments (closed-form count);
//  4. write the now-known exclusion range in place;
//  5. hash the file with the exclusion skipped and write the digest in place;
//  6. re-hash the hash.data assertion, update its hashed URI in the claim,
//     sign the claim and write claim and signature in place;
//  7. check that the final store has the placeholder's length (and bytes).
func JPEG(in []byte, opts *Options) ([]byte, error) {
	return signJPEG(in, opts, buildConfig{sigLen: esSignatureLen})
}

func signJPEG(in []byte, opts *Options, cfg buildConfig) ([]byte, error) {
	// 1. Placeholder manifest.
	m, err := build(opts, cfg)
	if err != nil {
		return nil, err
	}
	stripped, err := jpeg.Strip(in)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// 2. Serialise; this length is fixed from here on.
	store := m.Bytes()
	reserved := len(store)
	hdrLen := m.Store.HeaderLen()

	// 3. Insert the placeholder store.
	want := jpeg.SegmentCount(reserved)
	file, segs, err := jpeg.Insert(stripped, store)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if len(segs) != want {
		return nil, fmt.Errorf("sign: inserted %d APP11 segments, expected %d", len(segs), want)
	}
	start := segs[0].Offset
	length := jpeg.InsertedSize(reserved, hdrLen)
	if segs[len(segs)-1].End()-start != length {
		return nil, errors.New("sign: APP11 segments are not contiguous")
	}

	// Every backfilled value is written into the file in place and mirrored
	// into the store bytes, which step 7 checks.
	write := func(p patch) error {
		copy(store[p.off:], p.data)
		return jpeg.WriteStore(file, segs, hdrLen, p.off, p.data)
	}

	// 4. Exclusion: all inserted APP11 segments.
	p, err := m.SetExclusion(uint64(start), uint64(length))
	if err != nil {
		return nil, err
	}
	if err := write(p); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// 5. Hard-binding digest over everything outside the exclusion.
	h := sha256.New()
	h.Write(file[:start])
	h.Write(file[start+length:])
	if p, err = m.SetDigest(h.Sum(nil)); err != nil {
		return nil, err
	}
	if err := write(p); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// 6. Claim and signature.
	patches, err := m.Seal()
	if err != nil {
		return nil, err
	}
	for _, p := range patches {
		if err := write(p); err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
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
	st, err := jpeg.Extract(file)
	if err != nil || !bytes.Equal(st.JUMBF, final) {
		return nil, fmt.Errorf("sign: signed file does not carry the final manifest store: %v", err)
	}
	return file, nil
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
