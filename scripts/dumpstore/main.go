// Command dumpstore prints the C2PA manifest store of a JPEG or PNG as a
// JUMBF box tree, with CBOR content in diagnostic notation. A development aid.
//
// Usage: go run ./scripts/dumpstore <file>
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/fxamacker/cbor/v2"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dumpstore <file>")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var root *jumbf.Box
	if st, err := jpeg.Extract(b); err == nil {
		root = st.Root
	} else if st, err2 := png.Extract(b); err2 == nil {
		root = st.Root
	} else {
		fmt.Fprintln(os.Stderr, "dumpstore:", err, "/", err2)
		os.Exit(1)
	}
	dump(root, 0)
}

// longBytes matches byte strings over 64 bytes in diagnostic notation.
var longBytes = regexp.MustCompile(`h'[0-9a-f]{129,}'`)

func dump(b *jumbf.Box, depth int) {
	pad := strings.Repeat("  ", depth)
	switch {
	case b.IsSuperbox():
		d := b.Desc()
		fmt.Printf("%sjumb %q type=%s toggles=%#x\n", pad, d.Label, d.ContentType, d.Toggles)
		for _, c := range b.Contents() {
			dump(c, depth+1)
		}
	case b.Type == "cbor":
		diag, err := cbor.Diagnose(b.Payload)
		if err != nil {
			diag = "<bad CBOR: " + err.Error() + ">"
		}
		diag = longBytes.ReplaceAllStringFunc(diag, func(s string) string {
			return fmt.Sprintf("h'%s…'(%d bytes)", s[2:18], (len(s)-3)/2)
		})
		if len(diag) > 4000 {
			diag = diag[:4000] + "…"
		}
		fmt.Printf("%scbor %d bytes: %s\n", pad, len(b.Payload), diag)
	case b.Type == "json" || b.Type == "bfdb":
		fmt.Printf("%s%s %d bytes: %s\n", pad, b.Type, len(b.Payload), b.Payload)
	default:
		fmt.Printf("%s%s %d bytes\n", pad, b.Type, len(b.Payload))
	}
}
