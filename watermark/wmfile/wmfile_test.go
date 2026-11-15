package wmfile

import (
	"errors"
	"image"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
)

func TestFilesAndErrors(t *testing.T) {
	jpg, err := os.ReadFile(filepath.Join("..", "testdata", "IMG_0003.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := watermark.NewID()
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
	pngIn, _ := os.ReadFile(filepath.Join("..", "testdata", "sample1.png"))
	if out, err := EmbedFile(pngIn, id, &watermark.Options{Strength: 36}); err != nil {
		t.Error(err)
	} else if _, format, _ := Decode(out); format != "png" {
		t.Errorf("PNG in, %s out", format)
	}
	// WebP is read (here an unmarked one from the core fixtures), not written.
	webp, err := os.ReadFile(filepath.Join("..", "..", "testdata", "unsigned", "large.webp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractFile(webp); !errors.Is(err, watermark.ErrNotFound) {
		t.Errorf("unmarked WebP: %v", err)
	}
	if _, err := EmbedFile(webp, id, nil); !errors.Is(err, ErrNoEncoder) {
		t.Errorf("EmbedFile on WebP: %v", err)
	}
	small := image.NewNRGBA(image.Rect(0, 0, 100, 300))
	if _, _, err := Decode([]byte("not an image")); err == nil {
		t.Error("Decode of garbage succeeded")
	}
	if _, err := Encode(small, "webp"); !errors.Is(err, ErrNoEncoder) {
		t.Errorf("Encode webp: %v", err)
	}
}

// FuzzExtractFile: decoding and extracting never panic on any input.
func FuzzExtractFile(f *testing.F) {
	for _, name := range []string{"earth_apollo17.jpg"} {
		b, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ExtractFile(b)
	})
}
