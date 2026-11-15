package watermark

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/image/draw"
)

func load(t testing.TB, name string) image.Image {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	img, _, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

var photos = []string{"IMG_0003.jpg", "P1000827.jpg", "earth_apollo17.jpg", "sample1.png"}

func reJPEG(t *testing.T, img image.Image, q int) image.Image {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
		t.Fatal(err)
	}
	out, err := jpeg.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRoundTrip: the ID comes back from the watermarked image, after JPEG
// quality 70 and after halving the size; the change is far below visible
// (PSNR above 45 dB); the unmarked original has no watermark.
func TestRoundTrip(t *testing.T) {
	for i, name := range photos {
		t.Run(name, func(t *testing.T) {
			src := load(t, name)
			id := ID(0x0123456789ABCDEF + uint64(i))
			wm, err := Embed(src, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			if p := PSNR(src, wm); p < 45 {
				t.Errorf("PSNR %.1f dB, want above 45", p)
			}
			r, err := Extract(wm)
			if err != nil || r.ID != id || r.Confidence < 0.8 {
				t.Errorf("clean: %v, ID %s, confidence %.2f", err, r.ID, r.Confidence)
			}
			if r, err := Extract(reJPEG(t, wm, 70)); err != nil || r.ID != id {
				t.Errorf("JPEG 70: %v, ID %s", err, r.ID)
			}
			b := wm.Bounds()
			half := image.NewNRGBA(image.Rect(0, 0, b.Dx()/2, b.Dy()/2))
			draw.CatmullRom.Scale(half, half.Bounds(), wm, b, draw.Src, nil)
			if half.Bounds().Dx() >= MinSize && half.Bounds().Dy() >= MinSize {
				if r, err := Extract(half); err != nil || r.ID != id {
					t.Errorf("50 %%: %v, ID %s", err, r.ID)
				}
			}
			if n, err := BitErrors(wm, id); err != nil || n != 0 {
				t.Errorf("BitErrors = %d, %v", n, err)
			}
			if _, err := Extract(src); !errors.Is(err, ErrNotFound) {
				t.Errorf("unmarked original: %v", err)
			}
		})
	}
}

// TestNoFalsePositives runs Extract on images that carry no mark: random
// noise, flat grey, a gradient, and each photo.
func TestNoFalsePositives(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	noise := image.NewNRGBA(image.Rect(0, 0, 300, 200))
	for i := range noise.Pix {
		noise.Pix[i] = uint8(r.IntN(256))
	}
	grey := image.NewUniform(color.Gray{128})
	flat := image.NewNRGBA(image.Rect(0, 0, 256, 256))
	draw.Draw(flat, flat.Bounds(), grey, image.Point{}, draw.Src)
	grad := image.NewNRGBA(image.Rect(0, 0, 640, 480))
	for y := 0; y < 480; y++ {
		for x := 0; x < 640; x++ {
			grad.SetNRGBA(x, y, color.NRGBA{uint8(x * 255 / 639), uint8(y * 255 / 479), 90, 255})
		}
	}
	for name, img := range map[string]image.Image{"noise": noise, "flat": flat, "gradient": grad} {
		if _, err := Extract(img); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v, want ErrNotFound", name, err)
		}
	}
}

func TestFilesAndErrors(t *testing.T) {
	jpg, err := os.ReadFile(filepath.Join("testdata", "IMG_0003.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	out, err := EmbedFile(jpg, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := ExtractFile(out); err != nil || r.ID != id {
		t.Errorf("JPEG file: %v, %s", err, r.ID)
	}
	pngIn, _ := os.ReadFile(filepath.Join("testdata", "sample1.png"))
	if out, err := EmbedFile(pngIn, id, &Options{Strength: 36}); err != nil {
		t.Error(err)
	} else if _, format, _ := Decode(out); format != "png" {
		t.Errorf("PNG in, %s out", format)
	}
	// WebP is read (here an unmarked one from the core fixtures), not written.
	webp, err := os.ReadFile(filepath.Join("..", "testdata", "unsigned", "large.webp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractFile(webp); !errors.Is(err, ErrNotFound) {
		t.Errorf("unmarked WebP: %v", err)
	}
	if _, err := EmbedFile(webp, id, nil); !errors.Is(err, ErrNoEncoder) {
		t.Errorf("EmbedFile on WebP: %v", err)
	}
	small := image.NewNRGBA(image.Rect(0, 0, 100, 300))
	if _, err := Embed(small, id, nil); !errors.Is(err, ErrTooSmall) {
		t.Errorf("small: %v", err)
	}
	if _, err := Extract(small); !errors.Is(err, ErrTooSmall) {
		t.Errorf("small extract: %v", err)
	}
	if _, _, err := Decode([]byte("not an image")); err == nil {
		t.Error("Decode of garbage succeeded")
	}
	if _, err := Encode(small, "webp"); !errors.Is(err, ErrNoEncoder) {
		t.Errorf("Encode webp: %v", err)
	}
	if got, err := ParseID(id.String()); err != nil || got != id {
		t.Errorf("ParseID(String()) = %s, %v", got, err)
	}
	for _, bad := range []string{"", "123", "zzzzzzzzzzzzzzzz"} {
		if _, err := ParseID(bad); err == nil {
			t.Errorf("ParseID(%q) succeeded", bad)
		}
	}
}

// FuzzExtractFile: decoding and extracting never panic on any input.
func FuzzExtractFile(f *testing.F) {
	for _, name := range []string{"earth_apollo17.jpg"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ExtractFile(b)
	})
}
