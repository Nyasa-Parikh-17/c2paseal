// Package watermark embeds and extracts an invisible watermark that carries
// a 64-bit ID, so that a copy of an image whose C2PA manifest was stripped
// can be linked back to its manifest (a c2pa.soft-binding assertion records
// the ID).
//
// The method is a classic DWT-DCT one, written from scratch:
//
//   - The image's luminance is resampled to a fixed 512×512 working scale,
//     so the mark survives resizing (but not cropping, which shifts it).
//   - One level of Haar DWT; the low-low band is split into 4×4 blocks
//     (4096 of them) and each block's DCT DC coefficient carries one bit by
//     dithered quantisation index modulation (QIM) with a keyed dither.
//   - The payload is the ID plus a CRC-32 (96 bits); every bit is repeated
//     in about 42 blocks spread by a keyed permutation, and read back by a
//     soft majority vote. The CRC and a confidence threshold keep false
//     detections rare.
//   - The change made at the working scale is smoothed (so it has no block
//     edges), brought back to the image's size and added to R, G and B
//     equally (which changes luminance by exactly that much); a few
//     correction passes make the 8-bit result decode cleanly.
//   - Extraction tries a small grid of gains and offsets, which undoes a
//     uniform brightness or contrast change; the CRC-32 keeps the extra
//     tries from raising the false-detection rate.
//
// What it survives, and what it does not, is measured by cmd/wmharness and
// published in ROBUSTNESS.md. It is a fixed, public scheme: anyone with
// this code can read or remove the mark, so it links copies back to
// credentials; it does not prove anything by itself.
package watermark

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/draw"
	"math"
	mrand "math/rand/v2"
)

// ID is the 64-bit value a watermark carries.
type ID uint64

// String formats an ID as 16 hex digits.
func (id ID) String() string { return fmt.Sprintf("%016x", uint64(id)) }

// ParseID parses 16 hex digits.
func ParseID(s string) (ID, error) {
	var v uint64
	if len(s) != 16 {
		return 0, fmt.Errorf("watermark: ID %q: want 16 hex digits", s)
	}
	if _, err := fmt.Sscanf(s, "%016x", &v); err != nil {
		return 0, fmt.Errorf("watermark: ID %q: %w", s, err)
	}
	return ID(v), nil
}

// NewID returns a random ID.
func NewID() (ID, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return ID(binary.BigEndian.Uint64(b[:])), nil
}

const (
	workSize    = 512
	llSize      = workSize / 2
	blocksSide  = llSize / 4
	numBlocks   = blocksSide * blocksSide
	payloadBits = 96
	// MinSize is the smallest width and height that can carry a mark.
	MinSize = 128
	// DefaultStrength is the quantisation step in DC units; the mean of each
	// 8×8 working-scale area moves by at most Strength/16 grey levels.
	DefaultStrength = 28.0
	// minConfidence is the mean per-bit agreement below which a CRC match
	// is not trusted.
	minConfidence = 0.2
	maxPasses     = 8
)

// The gain and offset grid Extract searches: gains 0.80 to 1.20 in steps
// of 0.02, and offsets in sixteenths of the quantisation step.
var (
	searchGains = func() []float64 {
		var g []float64
		for i := -10; i <= 10; i++ {
			g = append(g, 1+float64(i)*0.02)
		}
		return g
	}()
	searchOffsets = 16
)

var (
	ErrTooSmall = fmt.Errorf("watermark: image smaller than %d×%d", MinSize, MinSize)
	ErrNotFound = errors.New("watermark: no watermark found")
)

// Options tune embedding. The zero value uses DefaultStrength.
type Options struct {
	Strength float64
}

// layout is the keyed, fixed part of the scheme: each block's dither and
// the bit it carries.
type layout struct {
	dither [numBlocks]float64 // in [0, 1), times the step
	bit    [numBlocks]int
}

var lay = func() *layout {
	var l layout
	r := mrand.New(mrand.NewPCG(0xC2FA5EA1, 0x5EA1C2FA))
	for i := range l.dither {
		l.dither[i] = r.Float64()
	}
	perm := r.Perm(numBlocks)
	for i, p := range perm {
		l.bit[i] = p % payloadBits
	}
	return &l
}()

// payload is the ID's 64 bits, then the CRC-32 (IEEE) of its 8 bytes.
func payload(id ID) [payloadBits]bool {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(id))
	crc := crc32.ChecksumIEEE(b[:])
	var out [payloadBits]bool
	for i := 0; i < 64; i++ {
		out[i] = uint64(id)>>(63-i)&1 == 1
	}
	for i := 0; i < 32; i++ {
		out[64+i] = crc>>(31-i)&1 == 1
	}
	return out
}

// toNRGBA returns a copy of img as *image.NRGBA with bounds at the origin.
func toNRGBA(img image.Image) *image.NRGBA {
	b := img.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)
	return out
}

// luma is BT.601 luminance of each pixel (alpha ignored).
func luma(img *image.NRGBA) *plane {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	pl := newPlane(w, h)
	for y := 0; y < h; y++ {
		row := img.Pix[y*img.Stride:]
		for x := 0; x < w; x++ {
			r, g, b := float64(row[4*x]), float64(row[4*x+1]), float64(row[4*x+2])
			pl.p[y*w+x] = 0.299*r + 0.587*g + 0.114*b
		}
	}
	return pl
}

// workLL is the LL band of the luminance at the working scale.
func workLL(img *image.NRGBA) *plane {
	return haarLL(resizeArea(luma(img), workSize, workSize))
}

// target returns the point of bit's lattice (dither + bit·step/2 + k·step)
// nearest to c.
func target(c, dither, step float64, bit bool) float64 {
	off := dither * step
	if bit {
		off += step / 2
	}
	return math.Round((c-off)/step)*step + off
}

// Embed returns a copy of img carrying id.
func Embed(img image.Image, id ID, opts *Options) (*image.NRGBA, error) {
	b := img.Bounds()
	if b.Dx() < MinSize || b.Dy() < MinSize {
		return nil, ErrTooSmall
	}
	step := DefaultStrength
	if opts != nil && opts.Strength > 0 {
		step = opts.Strength
	}
	bits := payload(id)
	out := toNRGBA(img)
	w, h := b.Dx(), b.Dy()
	for pass := 0; pass < maxPasses; pass++ {
		ll := workLL(out)
		dll := newPlane(llSize, llSize)
		changed := false
		for i := 0; i < numBlocks; i++ {
			bx, by := i%blocksSide, i/blocksSide
			c := blockDC(ll, bx, by)
			d := target(c, lay.dither[i], step, bits[lay.bit[i]]) - c
			if math.Abs(d) > step*0.05 {
				addBlockDC(dll, bx, by, d)
				changed = true
			}
		}
		if !changed {
			break
		}
		dy := resizeBilinear(smooth(haarLLInverseDelta(dll)), w, h)
		for y := 0; y < h; y++ {
			row := out.Pix[y*out.Stride:]
			for x := 0; x < w; x++ {
				d := dy.p[y*w+x]
				for c := 0; c < 3; c++ {
					row[4*x+c] = clamp8(float64(row[4*x+c]) + d)
				}
			}
		}
	}
	return out, nil
}

func clamp8(v float64) uint8 {
	v = math.Round(v)
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// Result is what Extract read.
type Result struct {
	ID ID
	// Confidence is the mean, over the 96 payload bits, of how strongly the
	// blocks carrying a bit agree (0: no agreement, 1: all blocks exact).
	Confidence float64
}

// Extract reads a watermark from img. It returns ErrNotFound when there is
// none, or when what it reads fails the CRC or is too weak to trust.
func Extract(img image.Image) (Result, error) {
	dcs, err := blockDCs(img)
	if err != nil {
		return Result{}, err
	}
	best := Result{}
	found := false
	for _, g := range searchGains {
		for k := 0; k < searchOffsets; k++ {
			soft := softBits(dcs, DefaultStrength, g, float64(k)/float64(searchOffsets))
			id, conf, ok := decode(soft)
			if conf > best.Confidence && (ok || !found) {
				if ok {
					found = true
				}
				best = Result{ID: id, Confidence: conf}
			}
		}
	}
	if !found || best.Confidence < minConfidence {
		return Result{Confidence: best.Confidence}, ErrNotFound
	}
	return best, nil
}

// decode turns soft bits into an ID; ok reports whether the CRC matches.
// conf is the mean strength of the bits.
func decode(soft [payloadBits]float64) (id ID, conf float64, ok bool) {
	var v uint64
	var crc uint32
	for i, s := range soft {
		bit := s < 0
		conf += math.Abs(s)
		if i < 64 {
			v <<= 1
			if bit {
				v |= 1
			}
		} else {
			crc <<= 1
			if bit {
				crc |= 1
			}
		}
	}
	conf /= payloadBits
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return ID(v), conf, crc32.ChecksumIEEE(b[:]) == crc
}

// blockDCs returns every block's DC coefficient at the working scale.
func blockDCs(img image.Image) ([]float64, error) {
	b := img.Bounds()
	if b.Dx() < MinSize || b.Dy() < MinSize {
		return nil, ErrTooSmall
	}
	ll := workLL(toNRGBA(img))
	dcs := make([]float64, numBlocks)
	for i := range dcs {
		dcs[i] = blockDC(ll, i%blocksSide, i/blocksSide)
	}
	return dcs, nil
}

// softBits returns, for each payload bit, the mean over its blocks of
// cos(2π·r), where r is the coefficient's position between lattice points
// after undoing a gain and an offset (a fraction of the step): +1 is a
// clean 0 bit, −1 a clean 1 bit.
func softBits(dcs []float64, step, gain, offset float64) [payloadBits]float64 {
	var soft [payloadBits]float64
	var n [payloadBits]int
	for i, c := range dcs {
		r := c/gain/step - offset - lay.dither[i]
		soft[lay.bit[i]] += math.Cos(2 * math.Pi * r)
		n[lay.bit[i]]++
	}
	for i := range soft {
		soft[i] /= float64(n[i])
	}
	return soft
}

// BitErrors returns how many of the 96 payload bits read from img differ
// from id's, at the gain and offset that fit best (for measuring
// robustness; 0 to 96).
func BitErrors(img image.Image, id ID) (int, error) {
	dcs, err := blockDCs(img)
	if err != nil {
		return 0, err
	}
	want := payload(id)
	least := payloadBits
	for _, g := range searchGains {
		for k := 0; k < searchOffsets; k++ {
			soft := softBits(dcs, DefaultStrength, g, float64(k)/float64(searchOffsets))
			errs := 0
			for i, s := range soft {
				if (s < 0) != want[i] {
					errs++
				}
			}
			least = min(least, errs)
		}
	}
	return least, nil
}

// PSNR returns the peak signal-to-noise ratio between two images of the
// same size over R, G and B, in dB (+Inf if identical).
func PSNR(a, b image.Image) float64 {
	na, nb := toNRGBA(a), toNRGBA(b)
	var se float64
	var n int
	for i := 0; i < len(na.Pix); i += 4 {
		for c := 0; c < 3; c++ {
			d := float64(na.Pix[i+c]) - float64(nb.Pix[i+c])
			se += d * d
			n++
		}
	}
	if se == 0 {
		return math.Inf(1)
	}
	return 10 * math.Log10(255*255/(se/float64(n)))
}
