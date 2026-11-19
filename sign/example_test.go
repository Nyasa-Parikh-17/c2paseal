package sign_test

import (
	"context"
	"fmt"
	"log"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

// OpenKey names the signing key by a URI, so the same code signs with a
// file in development and a KMS key in production. file: and plain paths
// are built in; importing the keys/awskms or keys/gcpkms module adds
// awskms: and gcpkms:.
func ExampleOpenKey() {
	signer, err := sign.OpenKey(context.Background(), "file:../testdata/pki/leaf.key")
	if err != nil {
		log.Fatal(err)
	}
	chain, err := c2paseal.LoadChain("../testdata/pki/leaf-chain.pem")
	if err != nil {
		log.Fatal(err)
	}
	m, err := sign.Build(&sign.Options{Chain: chain, Signer: signer, Title: "from a key URI"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(m.Claim.Title)
	fmt.Println(sign.KeySchemes())
	// Output:
	// from a key URI
	// [file]
}
