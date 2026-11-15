// Package wmfile reads and writes image files for the watermark package:
// decoding JPEG, PNG and WebP (golang.org/x/image), encoding JPEG and PNG,
// and watermarking or reading encoded files in one call. It is separate so
// that code with its own image decoding (the WebAssembly build, which lets
// the browser decode) links the watermark algorithm alone.
package wmfile

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"

	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
	_ "golang.org/x/image/webp" // decoder: WebP files can be read
)

// ErrNoEncoder is returned when asked to write a format that can only be
// read (WebP: the Go libraries decode it but have no encoder).
var ErrNoEncoder = errors.New("wmfile: no encoder for this format")

// Decode decodes a JPEG, PNG or WebP image and returns its format name.
func Decode(b []byte) (image.Image, string, error) {
	img, format, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, "", fmt.Errorf("wmfile: decode: %w", err)
	}
	return img, format, nil
}

// Encode encodes img as JPEG (quality 95) or PNG.
func Encode(img image.Image, format string) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	switch format {
	case "jpeg":
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95})
	case "png":
		err = png.Encode(&buf, img)
	default:
		return nil, fmt.Errorf("%w: %s", ErrNoEncoder, format)
	}
	if err != nil {
		return nil, fmt.Errorf("wmfile: encode %s: %w", format, err)
	}
	return buf.Bytes(), nil
}

// EmbedFile watermarks an encoded JPEG or PNG and re-encodes it in the
// same format (JPEG at quality 95). Watermark before signing: the mark
// changes the pixels, which the hard binding covers.
func EmbedFile(b []byte, id watermark.ID, opts *watermark.Options) ([]byte, error) {
	img, format, err := Decode(b)
	if err != nil {
		return nil, err
	}
	if format != "jpeg" && format != "png" {
		return nil, fmt.Errorf("%w: %s (watermark JPEG or PNG files)", ErrNoEncoder, format)
	}
	out, err := watermark.Embed(img, id, opts)
	if err != nil {
		return nil, err
	}
	return Encode(out, format)
}

// ExtractFile reads a watermark from an encoded JPEG, PNG or WebP.
func ExtractFile(b []byte) (watermark.Result, error) {
	img, _, err := Decode(b)
	if err != nil {
		return watermark.Result{}, err
	}
	return watermark.Extract(img)
}
