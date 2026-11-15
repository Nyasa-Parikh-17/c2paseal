package watermark

import "math"

// plane is a float image channel, row-major.
type plane struct {
	w, h int
	p    []float64
}

func newPlane(w, h int) *plane { return &plane{w: w, h: h, p: make([]float64, w*h)} }

func (pl *plane) at(x, y int) float64     { return pl.p[y*pl.w+x] }
func (pl *plane) set(x, y int, v float64) { pl.p[y*pl.w+x] = v }

// resizeArea downscales (or upscales) with box filtering: each output
// pixel averages the source area it covers, partial pixels weighted. It is
// separable, deterministic, and the same at embedding and extraction.
func resizeArea(src *plane, w, h int) *plane {
	tmp := newPlane(w, src.h)
	for y := 0; y < src.h; y++ {
		row := src.p[y*src.w : (y+1)*src.w]
		resample1D(row, tmp.p[y*w:(y+1)*w])
	}
	out := newPlane(w, h)
	col := make([]float64, src.h)
	dst := make([]float64, h)
	for x := 0; x < w; x++ {
		for y := 0; y < src.h; y++ {
			col[y] = tmp.p[y*w+x]
		}
		resample1D(col, dst)
		for y := 0; y < h; y++ {
			out.p[y*w+x] = dst[y]
		}
	}
	return out
}

// resample1D maps src onto dst by area coverage.
func resample1D(src, dst []float64) {
	n, m := len(src), len(dst)
	scale := float64(n) / float64(m)
	for i := range dst {
		lo, hi := float64(i)*scale, float64(i+1)*scale
		var sum, wsum float64
		for j := int(lo); j < n && float64(j) < hi; j++ {
			a := math.Max(lo, float64(j))
			b := math.Min(hi, float64(j+1))
			if b > a {
				sum += src[j] * (b - a)
				wsum += b - a
			}
		}
		if wsum > 0 {
			dst[i] = sum / wsum
		}
	}
}

// resizeBilinear upscales (or downscales) by bilinear interpolation, with
// pixel centres aligned; used to bring the embedding change from the
// working scale back to the image's size.
func resizeBilinear(src *plane, w, h int) *plane {
	out := newPlane(w, h)
	sx := float64(src.w) / float64(w)
	sy := float64(src.h) / float64(h)
	for y := 0; y < h; y++ {
		fy := math.Max(0, (float64(y)+0.5)*sy-0.5)
		y0 := min(int(fy), src.h-1)
		y1 := min(y0+1, src.h-1)
		ty := fy - float64(y0)
		for x := 0; x < w; x++ {
			fx := math.Max(0, (float64(x)+0.5)*sx-0.5)
			x0 := min(int(fx), src.w-1)
			x1 := min(x0+1, src.w-1)
			tx := fx - float64(x0)
			top := src.at(x0, y0)*(1-tx) + src.at(x1, y0)*tx
			bot := src.at(x0, y1)*(1-tx) + src.at(x1, y1)*tx
			out.set(x, y, top*(1-ty)+bot*ty)
		}
	}
	return out
}

// haarLL returns the low-low band of a one-level orthonormal Haar DWT
// (each value is the sum of a 2×2 block divided by 2). w and h are even.
func haarLL(src *plane) *plane {
	ll := newPlane(src.w/2, src.h/2)
	for y := 0; y < ll.h; y++ {
		for x := 0; x < ll.w; x++ {
			s := src.at(2*x, 2*y) + src.at(2*x+1, 2*y) + src.at(2*x, 2*y+1) + src.at(2*x+1, 2*y+1)
			ll.set(x, y, s/2)
		}
	}
	return ll
}

// haarLLInverseDelta turns a change of the LL band into the pixel change of
// the inverse transform with the other bands unchanged: each LL unit adds
// 1/2 to the four pixels of its block.
func haarLLInverseDelta(dll *plane) *plane {
	out := newPlane(dll.w*2, dll.h*2)
	for y := 0; y < dll.h; y++ {
		for x := 0; x < dll.w; x++ {
			d := dll.at(x, y) / 2
			out.set(2*x, 2*y, d)
			out.set(2*x+1, 2*y, d)
			out.set(2*x, 2*y+1, d)
			out.set(2*x+1, 2*y+1, d)
		}
	}
	return out
}

// blockDC returns the DC coefficient of the orthonormal 4×4 DCT-II of the
// block at (bx, by): the block's sum divided by 4.
func blockDC(ll *plane, bx, by int) float64 {
	var s float64
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			s += ll.at(bx*4+x, by*4+y)
		}
	}
	return s / 4
}

// addBlockDC adds d to a block's DC coefficient, which in the inverse DCT
// adds d/4 to each of its 16 values.
func addBlockDC(ll *plane, bx, by int, d float64) {
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			ll.set(bx*4+x, by*4+y, ll.at(bx*4+x, by*4+y)+d/4)
		}
	}
}

// smooth blurs a plane with the separable binomial kernel [1 4 6 4 1]/16,
// edges clamped, so the per-block changes have no visible block edges.
func smooth(src *plane) *plane {
	k := [5]float64{1.0 / 16, 4.0 / 16, 6.0 / 16, 4.0 / 16, 1.0 / 16}
	tmp := newPlane(src.w, src.h)
	for y := 0; y < src.h; y++ {
		for x := 0; x < src.w; x++ {
			var v float64
			for i, kv := range k {
				xx := min(max(x+i-2, 0), src.w-1)
				v += src.at(xx, y) * kv
			}
			tmp.set(x, y, v)
		}
	}
	out := newPlane(src.w, src.h)
	for y := 0; y < src.h; y++ {
		for x := 0; x < src.w; x++ {
			var v float64
			for i, kv := range k {
				yy := min(max(y+i-2, 0), src.h-1)
				v += tmp.at(x, yy) * kv
			}
			out.set(x, y, v)
		}
	}
	return out
}
