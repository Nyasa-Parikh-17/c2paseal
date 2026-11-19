package c2paseal_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Nyasa-Parikh-17/c2paseal"
)

// Read decodes the manifest store embedded in a file. It does not verify
// anything; use Verify or VerifyFile for that.
func ExampleRead() {
	store, err := c2paseal.Read("testdata/signed/small.jpg")
	if err != nil {
		log.Fatal(err)
	}
	m := store.Active
	fmt.Println("format:", store.Format)
	fmt.Println("manifests:", len(store.Manifests))
	fmt.Println("generator:", m.Claim.ClaimGeneratorInfo.Name(), m.Claim.ClaimGeneratorInfo.Version())
	fmt.Println("title:", m.Claim.Title)
	for _, a := range m.Assertions { // in store order
		fmt.Println("assertion:", a.Label)
	}
	// Output:
	// format: jpeg
	// manifests: 1
	// generator: c2paseal-fixtures 1.0
	// title: small.jpg
	// assertion: c2pa.thumbnail.claim
	// assertion: c2pa.actions.v2
	// assertion: c2pa.hash.data
}

// VerifyFile validates a file and reports C2PA status codes. Without trust
// anchors a correctly signed file is Valid but its signer is untrusted;
// with the signer's root as an anchor it is Trusted.
func ExampleVerifyFile() {
	r := c2paseal.VerifyFile("testdata/signed/small.jpg", nil)
	fmt.Println("no anchors:", r.State())

	// The TEST ONLY root from testdata/pki; use real C2PA trust anchors in
	// production.
	anchors, err := c2paseal.LoadTrustAnchors("testdata/pki/trust-anchors.pem")
	if err != nil {
		log.Fatal(err)
	}
	r = c2paseal.VerifyFile("testdata/signed/small.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
	fmt.Println("test root trusted:", r.State())

	// A file whose image bytes were changed after signing.
	r = c2paseal.VerifyFile("testdata/broken/data-flip.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
	fmt.Println("tampered:", r.State())
	for _, s := range r.ActiveManifest {
		if s.Kind().String() == "failure" {
			fmt.Println("  failure:", s.Code)
		}
	}
	// Output:
	// no anchors: Valid
	// test root trusted: Trusted
	// tampered: Invalid
	//   failure: assertion.dataHash.mismatch
}

// Verify is the shortest way to get the status codes of a file.
func ExampleVerify() {
	for _, s := range c2paseal.Verify("testdata/unsigned/small.png", nil) {
		fmt.Println(s.Code)
	}
	// Output:
	// claim.missing
}

// Sign embeds a newly signed manifest in a JPEG, PNG, WebP, HEIC or AVIF
// file. The TEST ONLY
// certificates in testdata/pki work out of the box; their private key is
// public, so files signed with them prove nothing.
func ExampleSign() {
	chain, key, err := c2paseal.LoadSigner("testdata/pki/leaf-chain.pem", "testdata/pki/leaf.key")
	if err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "c2paseal-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "signed.png")

	err = c2paseal.Sign("testdata/unsigned/small.png", out, &c2paseal.SignOptions{
		Chain:  chain,
		Signer: key,
		Title:  "My picture",
		// TSAURL: "http://timestamp.digicert.com", // optional RFC 3161 time-stamp
	})
	if err != nil {
		log.Fatal(err)
	}

	store, err := c2paseal.Read(out)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("title:", store.Active.Claim.Title)
	fmt.Println("generator:", store.Active.Claim.ClaimGeneratorInfo.Name())
	for _, s := range c2paseal.Verify(out, nil) {
		if s.Kind().String() == "failure" {
			fmt.Println("failure:", s.Code) // only the untrusted test signer
		}
	}
	// Output:
	// title: My picture
	// generator: C2paSeal
	// failure: signingCredential.untrusted
}

// SignAsset signs a file held in memory. With Sidecar the manifest store is
// kept out of the file and returned, to save next to it as a .c2pa file (or
// to serve at RemoteURL); VerifyBytes then takes it as ManifestStore.
func ExampleSignAsset() {
	chain, key, err := c2paseal.LoadSigner("testdata/pki/leaf-chain.pem", "testdata/pki/leaf.key")
	if err != nil {
		log.Fatal(err)
	}
	photo, err := os.ReadFile("testdata/unsigned/small.webp")
	if err != nil {
		log.Fatal(err)
	}
	signed, err := c2paseal.SignAsset(photo, &c2paseal.SignOptions{Chain: chain, Signer: key, Sidecar: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("file unchanged:", string(signed.File) == string(photo))
	fmt.Println("sidecar path:", c2paseal.SidecarPath("photos/small.webp"))

	anchors, err := c2paseal.LoadTrustAnchors("testdata/pki/trust-anchors.pem")
	if err != nil {
		log.Fatal(err)
	}
	r := c2paseal.VerifyBytes(signed.File, &c2paseal.VerifyOptions{TrustAnchors: anchors, ManifestStore: signed.Store})
	fmt.Println("with its sidecar:", r.State())
	// Output:
	// file unchanged: true
	// sidecar path: photos/small.c2pa
	// with its sidecar: Trusted
}

// VerifyBytes validates a file held in memory. Bad input is never a Go
// error: a file C2paSeal cannot handle is reported as Invalid with a
// general.error status that says what the file looks like. C2paSeal handles
// images only (JPEG, PNG, WebP, HEIC and AVIF).
func ExampleVerifyBytes() {
	mp4 := []byte("\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41")
	r := c2paseal.VerifyBytes(mp4, nil)
	fmt.Println(r.State())
	for _, s := range r.Statuses() {
		fmt.Println(s.Code)
		fmt.Println(s.Explanation)
	}
	// Output:
	// Invalid
	// general.error
	// unsupported file format: the file looks like an MP4 video (or another ISO BMFF file that is not HEIC or AVIF); C2paSeal supports JPEG, PNG, WebP, HEIC and AVIF images only
}

// DetectFormat names a supported image from its leading bytes, or returns
// "" for anything else.
func ExampleDetectFormat() {
	for _, name := range []string{"small.jpg", "small.png", "small.webp", "sample.heic", "sample.avif"} {
		b, err := os.ReadFile(filepath.Join("testdata", "unsigned", name))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(name, c2paseal.DetectFormat(b))
	}
	fmt.Printf("GIF %q\n", c2paseal.DetectFormat([]byte("GIF89a")))
	// Output:
	// small.jpg jpeg
	// small.png png
	// small.webp webp
	// sample.heic heic
	// sample.avif avif
	// GIF ""
}
