// Command genimages writes the unsigned fixture originals used by
// scripts/make-fixtures.sh. Output is deterministic.
//
// Usage: go run ./scripts/genimages <outdir>
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genimages <outdir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "genimages:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	small := gradient(64, 48)
	// Noise compresses badly, so the signed file's thumbnail pushes the
	// manifest store past one APP11 segment (64 KiB).
	large := noise(480, 360)

	files := []struct {
		name string
		data func() ([]byte, error)
	}{
		{"small.jpg", func() ([]byte, error) { return encJPEG(small) }},
		{"exif.jpg", func() ([]byte, error) { b, err := encJPEG(small); return withExif(b), err }},
		{"large.jpg", func() ([]byte, error) { return encJPEG(large) }},
		{"small.png", func() ([]byte, error) { return encPNG(small) }},
		{"large.png", func() ([]byte, error) { return encPNG(noise(256, 192)) }},
	}
	for _, f := range files {
		b, err := f.data()
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func gradient(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{uint8(x * 255 / w), uint8(y * 255 / h), 128, 255})
		}
	}
	return img
}

func noise(w, h int) image.Image {
	r := rand.New(rand.NewPCG(1, 2))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = uint8(r.UintN(256))
	}
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	return img
}

func encJPEG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90})
	return buf.Bytes(), err
}

func encPNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	return buf.Bytes(), err
}

// withExif inserts a minimal APP1 Exif segment (empty little-endian TIFF
// IFD) right after SOI, so fixtures cover a JPEG whose APP11 must follow APP1.
func withExif(jpg []byte) []byte {
	payload := []byte("Exif\x00\x00" + "II*\x00\x08\x00\x00\x00" + "\x00\x00" + "\x00\x00\x00\x00")
	n := len(payload) + 2
	seg := append([]byte{0xFF, 0xE1, byte(n >> 8), byte(n)}, payload...)
	out := append([]byte{}, jpg[:2]...)
	out = append(out, seg...)
	return append(out, jpg[2:]...)
}
