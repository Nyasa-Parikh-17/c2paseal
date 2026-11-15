// Command verify-folder checks the Content Credentials of every image in a
// folder and prints one line per file, like a CI gate.
//
//	go run ./verify-folder --trust C2PA-TRUST-LIST.pem photos/
//
// It exits with status 1 if any image has no credentials or invalid ones.
// With --require-trusted, a signer missing from the trust list also fails.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func main() {
	ok, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-folder:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

// run returns whether every image passed.
func run(args []string, stdout io.Writer) (bool, error) {
	flags := flag.NewFlagSet("verify-folder", flag.ContinueOnError)
	var trust multi
	flags.Var(&trust, "trust", "PEM trust anchors (repeatable)")
	requireTrusted := flags.Bool("require-trusted", false, "fail when the signer is not on the trust list")
	if err := flags.Parse(args); err != nil {
		return false, err
	}
	if flags.NArg() != 1 {
		return false, errors.New("usage: verify-folder [--trust roots.pem]... [--require-trusted] folder")
	}
	opts := &c2paseal.VerifyOptions{}
	for _, t := range trust {
		a, err := c2paseal.LoadTrustAnchors(t)
		if err != nil {
			return false, err
		}
		opts.TrustAnchors = append(opts.TrustAnchors, a...)
	}

	allOK, n := true, 0
	err := filepath.WalkDir(flags.Arg(0), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isImage(p) {
			return err
		}
		n++
		res := c2paseal.VerifyFile(p, opts)
		state := res.State()
		var failures []string
		for _, s := range res.Statuses() {
			if s.Kind() == verify.Failure {
				failures = append(failures, s.Code)
			}
		}
		pass := state == verify.Trusted || (state == verify.Valid && !*requireTrusted)
		mark := "ok  "
		if !pass {
			mark, allOK = "FAIL", false
		}
		line := fmt.Sprintf("%s %-8s %s", mark, state, p)
		if len(failures) > 0 {
			line += "  (" + strings.Join(failures, ", ") + ")"
		}
		fmt.Fprintln(stdout, line)
		return nil
	})
	if err != nil {
		return false, err
	}
	fmt.Fprintf(stdout, "%d images checked\n", n)
	return allOK, nil
}

func isImage(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".avif":
		return true
	}
	return false
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
