// Command watermark-recover shows how Content Credentials are recovered for
// a copy that lost them, without a server:
//
//  1. watermark a photo with a random ID and sign it, recording the ID in a
//     c2pa.soft-binding assertion;
//
//  2. keep the manifest store in a local folder, under the ID;
//
//  3. make a copy without credentials, re-encoded as JPEG quality 80, as a
//     social network or messaging app would;
//
//  4. read the watermark from the copy, look its manifest store up, and
//     verify the store against the copy.
//
//     go run ./watermark-recover --cert chain.pem --key key.pem [--trust roots.pem] photo.jpg
//
// sealstore (cmd/sealstore) does the same with a shared HTTP store.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark/wmfile"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "watermark-recover:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("watermark-recover", flag.ContinueOnError)
	cert := fs.String("cert", "", "PEM certificate chain, signer first")
	key := fs.String("key", "", "PEM private key (ECDSA P-256)")
	trust := fs.String("trust", "", "PEM trust anchors (optional)")
	dir := fs.String("dir", "manifests", "the local manifest store folder")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *cert == "" || *key == "" {
		return errors.New("usage: watermark-recover --cert chain.pem --key key.pem [--trust roots.pem] photo.jpg")
	}
	photo, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	chain, signer, err := c2paseal.LoadSigner(*cert, *key)
	if err != nil {
		return err
	}

	// 1. Watermark first (it changes pixels), then sign with the soft binding.
	id, err := watermark.NewID()
	if err != nil {
		return err
	}
	marked, err := wmfile.EmbedFile(photo, id, nil)
	if err != nil {
		return err
	}
	signed, err := c2paseal.SignAsset(marked, &c2paseal.SignOptions{
		Chain:        chain,
		Signer:       signer,
		SoftBindings: []sign.SoftBinding{{Alg: watermark.SoftBindingAlg, Value: id.String()}},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "1. signed, watermark ID %s\n", id)

	// 2. Keep the manifest store under its ID.
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, id.String()+".c2pa"), signed.Store, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "2. manifest store saved in %s\n", *dir)

	// 3. A copy without credentials: decoded and re-encoded.
	img, _, err := wmfile.Decode(signed.File)
	if err != nil {
		return err
	}
	var copyBuf bytes.Buffer
	if err := jpeg.Encode(&copyBuf, img, &jpeg.Options{Quality: 80}); err != nil {
		return err
	}
	stripped := copyBuf.Bytes()
	if r := c2paseal.VerifyBytes(stripped, nil); r.State() != verify.Invalid {
		return errors.New("the copy still has credentials")
	}
	fmt.Fprintf(stdout, "3. copy without credentials: %d bytes, JPEG quality 80\n", len(stripped))

	// 4. Recover: watermark → ID → manifest store → verify against the copy.
	found, err := wmfile.ExtractFile(stripped)
	if err != nil {
		return fmt.Errorf("no watermark in the copy: %w", err)
	}
	store, err := os.ReadFile(filepath.Join(*dir, found.ID.String()+".c2pa"))
	if err != nil {
		return fmt.Errorf("watermark %s: no manifest store: %w", found.ID, err)
	}
	opts := &c2paseal.VerifyOptions{ManifestStore: store}
	if *trust != "" {
		if opts.TrustAnchors, err = c2paseal.LoadTrustAnchors(*trust); err != nil {
			return err
		}
	}
	res := c2paseal.VerifyBytes(stripped, opts)
	signatureOK, bytesChanged := false, false
	for _, s := range res.Statuses() {
		switch s.Code {
		case verify.ClaimSignatureValidated:
			signatureOK = true
		case verify.AssertionDataHashMismatch:
			bytesChanged = true
		}
	}
	fmt.Fprintf(stdout, "4. watermark %s read (confidence %.2f); signature valid: %v; copy's bytes changed since signing: %v\n",
		found.ID, found.Confidence, signatureOK, bytesChanged)
	if !signatureOK {
		return errors.New("the recovered manifest's signature did not validate")
	}
	return nil
}
