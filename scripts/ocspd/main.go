// Command ocspd runs the TEST ONLY OCSP responder (internal/testocsp) for
// the signers in <pki>/ocsp, for fixture scripts and the interop harness.
// It exits by itself after the given lifetime, since kill cannot always
// stop it on Windows.
//
//	ocspd <addr> <pki-dir> [lifetime-seconds]
package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/testocsp"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ocspd <addr> <pki-dir> [lifetime-seconds]")
		os.Exit(2)
	}
	r, err := testocsp.Load(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ocspd:", err)
		os.Exit(1)
	}
	if len(os.Args) > 3 {
		if s, err := strconv.Atoi(os.Args[3]); err == nil {
			time.AfterFunc(time.Duration(s)*time.Second, func() { os.Exit(0) })
		}
	}
	srv := &http.Server{Addr: os.Args[1], Handler: r, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "ocspd:", err)
		os.Exit(1)
	}
}
