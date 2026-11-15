# watermark

An invisible watermark that carries a 64-bit ID, so that a copy of an image
whose Content Credentials were stripped can be linked back to them. It is
written from scratch in Go (no CGO). This is its own module: it depends on
`golang.org/x/image`, for WebP decoding and resizing, and the core C2paSeal
module does not.

```go
id, _ := watermark.NewID()
marked, err := wmfile.EmbedFile(jpegBytes, id, nil) // re-encoded, JPEG quality 95
// ... sign `marked` with C2paSeal (watermark first: the mark changes pixels),
// recording id in a c2pa.soft-binding (alg watermark.SoftBindingAlg) ...

r, err := wmfile.ExtractFile(someCopy) // JPEG, PNG or WebP
if err == nil {
	fmt.Println(r.ID, r.Confidence)
}
```

There are two packages. `watermark` is the algorithm (`Embed` and `Extract`
on an `image.Image`), standard library only. `watermark/wmfile` reads and
writes files, using `golang.org/x/image` for WebP. The WebAssembly build
links only the first, because the browser decodes the image itself.
[sealstore](../cmd/sealstore) puts it all together: watermark, sign, store,
recover.

**How it works:**
- The luminance is resampled to 512×512.
- One level of Haar DWT; the low band is cut into 4,096 4×4 blocks.
- Each block's DCT DC coefficient carries one bit by dithered quantisation
  (QIM).
- The 96-bit payload (the ID plus a CRC-32) is repeated about 42 times and
  read by a soft majority vote.
- When reading, `Extract` searches a small grid of gains and offsets, so
  brightness, contrast and mild gamma changes do not lose the mark.

**What it survives:** see [ROBUSTNESS.md](ROBUSTNESS.md). CI regenerates it
with `go run ./cmd/wmharness`. The short version:
- It survives JPEG down to quality 50, resizing, noise, brightness,
  contrast and gamma changes, and a tightly cropped screenshot.
- It does **not** survive cropping, even 2 %, or anything that shifts the
  image, such as a screenshot with a border.
- PSNR is about 49 dB. When zoomed in on large flat dark areas, a faint
  mottling can be seen.

**What it is not:** a security feature. The scheme is public, so anyone with
this code can read or remove the mark. It links a copy back to its
credentials; those credentials are what prove anything, and C2paSeal
verifies them against the image.

Images must be at least 128×128. Watermarking writes JPEG or PNG only,
because the Go libraries have no WebP encoder. WebP is read only.
