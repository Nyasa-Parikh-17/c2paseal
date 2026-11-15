// Command sign-and-verify is the smallest C2paSeal program: it signs an
// image and verifies the result.
//
//	go run ./sign-and-verify --cert chain.pem --key key.pem --trust roots.pem photo.jpg
//
// It writes photo.signed.jpg next to the input and prints the verdict.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sign-and-verify:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign-and-verify", flag.ContinueOnError)
	cert := fs.String("cert", "", "PEM certificate chain, signer first")
	key := fs.String("key", "", "PEM private key (ECDSA P-256)")
	trust := fs.String("trust", "", "PEM trust anchors (optional)")
	title := fs.String("title", "", "claim title (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *cert == "" || *key == "" {
		return errors.New("usage: sign-and-verify --cert chain.pem --key key.pem [--trust roots.pem] image")
	}
	in := fs.Arg(0)
	ext := filepath.Ext(in)
	out := strings.TrimSuffix(in, ext) + ".signed" + ext

	// 1. Sign.
	chain, signer, err := c2paseal.LoadSigner(*cert, *key)
	if err != nil {
		return err
	}
	if err := c2paseal.Sign(in, out, &c2paseal.SignOptions{Chain: chain, Signer: signer, Title: *title}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed: %s\n", out)

	// 2. Verify. Without trust anchors the best verdict is Valid: intact,
	// but nobody vouches for the signer.
	opts := &c2paseal.VerifyOptions{}
	if *trust != "" {
		if opts.TrustAnchors, err = c2paseal.LoadTrustAnchors(*trust); err != nil {
			return err
		}
	}
	res := c2paseal.VerifyFile(out, opts)
	fmt.Fprintf(stdout, "state: %s\n", res.State())
	for _, s := range res.Statuses() {
		fmt.Fprintf(stdout, "  %-8s %s\n", s.Kind(), s.Code)
	}
	return nil
}
