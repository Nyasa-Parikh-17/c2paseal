// Command wmharness measures how well the watermark survives common edits
// and writes the results as Markdown (ROBUSTNESS.md), failures included.
// Everything is deterministic, so CI regenerates the file and fails if the
// committed one is out of date (-check).
//
//	go run ./cmd/wmharness [-check] [-o ROBUSTNESS.md] [testdata images...]
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark/wmfile"
	"golang.org/x/image/draw"
)

// attack is one edit applied to a watermarked image.
type attack struct {
	group, name string
	apply       func(image.Image) image.Image
}

func jpegQ(q int) func(image.Image) image.Image {
	return func(img image.Image) image.Image {
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
			panic(err)
		}
		out, err := jpeg.Decode(&buf)
		if err != nil {
			panic(err)
		}
		return out
	}
}

func pngRoundTrip(img image.Image) image.Image {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	out, err := png.Decode(&buf)
	if err != nil {
		panic(err)
	}
	return out
}

func scale(f float64) func(image.Image) image.Image {
	return func(img image.Image) image.Image {
		b := img.Bounds()
		w, h := int(math.Round(float64(b.Dx())*f)), int(math.Round(float64(b.Dy())*f))
		out := image.NewNRGBA(image.Rect(0, 0, w, h))
		draw.CatmullRom.Scale(out, out.Bounds(), img, b, draw.Src, nil)
		return out
	}
}

// crop cuts frac of the width and height away, split between the edges
// (centre) or all from the right and bottom (corner).
func crop(frac float64, centre bool) func(image.Image) image.Image {
	return func(img image.Image) image.Image {
		b := img.Bounds()
		dx, dy := int(float64(b.Dx())*frac), int(float64(b.Dy())*frac)
		r := image.Rect(b.Min.X, b.Min.Y, b.Max.X-dx, b.Max.Y-dy)
		if centre {
			r = image.Rect(b.Min.X+dx/2, b.Min.Y+dy/2, b.Max.X-(dx-dx/2), b.Max.Y-(dy-dy/2))
		}
		out := image.NewNRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
		draw.Draw(out, out.Bounds(), img, r.Min, draw.Src)
		return out
	}
}

// adjust maps every R, G, B value through f.
func adjust(f func(float64) float64) func(image.Image) image.Image {
	return func(img image.Image) image.Image {
		b := img.Bounds()
		out := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
		draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)
		var lut [256]uint8
		for i := range lut {
			lut[i] = clamp(f(float64(i)))
		}
		for i := 0; i < len(out.Pix); i += 4 {
			out.Pix[i], out.Pix[i+1], out.Pix[i+2] = lut[out.Pix[i]], lut[out.Pix[i+1]], lut[out.Pix[i+2]]
		}
		return out
	}
}

func noise(sigma float64) func(image.Image) image.Image {
	return func(img image.Image) image.Image {
		r := rand.New(rand.NewPCG(7, 11))
		b := img.Bounds()
		out := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
		draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)
		for i := 0; i < len(out.Pix); i += 4 {
			for c := 0; c < 3; c++ {
				out.Pix[i+c] = clamp(float64(out.Pix[i+c]) + r.NormFloat64()*sigma)
			}
		}
		return out
	}
}

// screenshot imitates taking a screenshot of the image shown on screen and
// sharing it: displayed at 90 %, with a 12-pixel window border, slightly
// brighter, saved as JPEG 85. The border makes it a small crop-like shift.
func screenshot(img image.Image) image.Image {
	s := scale(0.9)(img)
	b := s.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, b.Dx()+24, b.Dy()+24))
	draw.Draw(out, out.Bounds(), &image.Uniform{color.NRGBA{240, 240, 240, 255}}, image.Point{}, draw.Src)
	draw.Draw(out, image.Rect(12, 12, 12+b.Dx(), 12+b.Dy()), s, b.Min, draw.Src)
	return jpegQ(85)(adjust(func(v float64) float64 { return v + 3 })(out))
}

// screenshotTight is the same without the border (the screenshot cropped
// to the image).
func screenshotTight(img image.Image) image.Image {
	return jpegQ(85)(adjust(func(v float64) float64 { return v + 3 })(scale(0.9)(img)))
}

func then(fs ...func(image.Image) image.Image) func(image.Image) image.Image {
	return func(img image.Image) image.Image {
		for _, f := range fs {
			img = f(img)
		}
		return img
	}
}

func clamp(v float64) uint8 { return uint8(math.Max(0, math.Min(255, math.Round(v)))) }

var attacks = []attack{
	{"Lossless", "PNG round trip", pngRoundTrip},
	{"JPEG", "quality 95", jpegQ(95)},
	{"JPEG", "quality 90", jpegQ(90)},
	{"JPEG", "quality 80", jpegQ(80)},
	{"JPEG", "quality 70", jpegQ(70)},
	{"JPEG", "quality 60", jpegQ(60)},
	{"JPEG", "quality 50", jpegQ(50)},
	{"Resize", "50 %", scale(0.5)},
	{"Resize", "75 %", scale(0.75)},
	{"Resize", "125 %", scale(1.25)},
	{"Resize", "50 %, then JPEG 75", then(scale(0.5), jpegQ(75))},
	{"Crop", "2 % (centre)", crop(0.02, true)},
	{"Crop", "5 % (centre)", crop(0.05, true)},
	{"Crop", "10 % (centre)", crop(0.10, true)},
	{"Crop", "25 % (right and bottom)", crop(0.25, false)},
	{"Screenshot", "90 %, +3 brightness, JPEG 85", screenshotTight},
	{"Screenshot", "same, with a 12 px window border", screenshot},
	// Brightness shifts every block's DC by 8× the change: +5, +10 and +17
	// shift it by 1.43, 2.86 and 4.86 quantisation steps (28). Without the
	// offset search, +5 (almost a half step) inverted every bit.
	{"Colour", "brightness +5", adjust(func(v float64) float64 { return v + 5 })},
	{"Colour", "brightness +10", adjust(func(v float64) float64 { return v + 10 })},
	{"Colour", "brightness +17", adjust(func(v float64) float64 { return v + 17 })},
	{"Colour", "contrast ×0.9", adjust(func(v float64) float64 { return 128 + (v-128)*0.9 })},
	{"Colour", "gamma 1.2", adjust(func(v float64) float64 { return 255 * math.Pow(v/255, 1/1.2) })},
	{"Noise", "Gaussian σ = 3", noise(3)},
}

// testID is the ID embedded in every image (any fixed value would do).
const testID = watermark.ID(0xC2FA5EA1D0C0FFEE)

func main() {
	check := flag.Bool("check", false, "fail if the output file differs from what this run produces")
	outPath := flag.String("o", "ROBUSTNESS.md", "where to write the results")
	flag.Parse()
	files := flag.Args()
	if len(files) == 0 {
		files, _ = filepath.Glob("testdata/*")
	}
	md, err := run(files)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wmharness:", err)
		os.Exit(1)
	}
	if *check {
		old, err := os.ReadFile(*outPath)
		if err != nil || !bytes.Equal(bytes.ReplaceAll(old, []byte("\r\n"), []byte("\n")), md) {
			fmt.Fprintf(os.Stderr, "wmharness: %s is out of date; run go run ./cmd/wmharness and commit it\n", *outPath)
			os.Exit(1)
		}
		fmt.Println("wmharness:", *outPath, "is up to date")
		return
	}
	if err := os.WriteFile(*outPath, md, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "wmharness:", err)
		os.Exit(1)
	}
	fmt.Println("wmharness: wrote", *outPath)
}

type cell struct {
	ok   bool
	bits int
	conf float64
}

func run(files []string) ([]byte, error) {
	type img struct {
		name     string
		w, h     int
		psnr     float64
		orig, wm image.Image
	}
	var imgs []img
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		src, _, err := wmfile.Decode(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		wm, err := watermark.Embed(src, testID, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		imgs = append(imgs, img{filepath.Base(f), src.Bounds().Dx(), src.Bounds().Dy(), watermark.PSNR(src, wm), src, wm})
	}

	results := make([][]cell, len(attacks))
	for i, a := range attacks {
		for _, im := range imgs {
			att := a.apply(im.wm)
			r, err := watermark.Extract(att)
			bits, _ := watermark.BitErrors(att, testID)
			results[i] = append(results[i], cell{ok: err == nil && r.ID == testID, bits: bits, conf: r.Confidence})
		}
	}

	var w strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&w, format, a...) }
	p("# Watermark robustness\n\n")
	p("Generated by `go run ./cmd/wmharness`; CI regenerates it and fails if it changes. Do not edit by hand.\n\n")
	p("Each image gets the same 64-bit ID with the default strength; each edit is applied to the watermarked image, then `Extract` must return exactly that ID. ")
	p("✓ means recovered; ✗ means not (Extract reports no watermark: the CRC failed or the read was too weak). ")
	p("The number is how many of the 96 payload bits (ID + CRC-32) were read wrong at the best-fitting gain and offset; a ✗ with few wrong bits was close.\n\n")
	p("## Images\n\n| Image | Size | PSNR of the watermarked image |\n|---|---|---|\n")
	for _, im := range imgs {
		p("| `%s` | %d×%d | %.1f dB |\n", im.name, im.w, im.h, im.psnr)
	}
	p("\nThe images are from the c2pa-rs test corpus (MIT OR Apache-2.0). A PSNR above about 40 dB is not visible.\n\n")
	p("## Results\n\n| Edit | |")
	for _, im := range imgs {
		p(" `%s` |", im.name)
	}
	p(" Recovered |\n|---|---|")
	for range imgs {
		p("---|")
	}
	p("---|\n")
	total, okAll := 0, 0
	for i, a := range attacks {
		n := 0
		p("| %s | %s |", a.group, a.name)
		for _, c := range results[i] {
			mark := "✗"
			if c.ok {
				mark = "✓"
				n++
			}
			p(" %s %d |", mark, c.bits)
		}
		p(" %d/%d |\n", n, len(imgs))
		total += len(imgs)
		okAll += n
	}
	p("\n**Summary:** recovered in %d of %d cases.\n\n", okAll, total)

	// False positives: the unmarked originals, and the originals after JPEG.
	p("## False positives\n\nExtract on images that were never watermarked must find nothing.\n\n| Image | Original | JPEG 75 |\n|---|---|---|\n")
	fp := 0
	for _, im := range imgs {
		_, e1 := watermark.Extract(im.orig)
		_, e2 := watermark.Extract(jpegQ(75)(im.orig))
		s := func(err error) string {
			if err == nil {
				fp++
				return "**found (false positive)**"
			}
			return "none"
		}
		p("| `%s` | %s | %s |\n", im.name, s(e1), s(e2))
	}
	p("\nFalse positives: %d.\n\n", fp)
	p("## Reading the results\n\n")
	p("- The mark lives in the image's coarse brightness pattern at a fixed working scale, so re-compression, resizing and mild noise leave it readable.\n")
	p("- Cropping shifts the pattern against the working grid, and colour changes move the brightness levels the bits are quantised to; those are the expected failures of this kind of watermark.\n")
	p("- Brightness, contrast and mild gamma changes are undone by the gain and offset search in `Extract`.\n")
	p("- A screenshot that includes the window border is a crop in disguise.\n")
	p("- Visibility: at about 49 dB the change is invisible at normal viewing size; zoomed in on large flat dark areas, a faint soft mottling can be seen.\n")
	p("- The scheme is public and unkeyed in practice: it is meant to link stripped copies back to their credentials, not to resist someone removing it on purpose.\n")
	return []byte(w.String()), nil
}
