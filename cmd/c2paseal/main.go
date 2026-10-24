// Command c2paseal inspects and verifies C2PA Content Credentials in JPEG
// and PNG files.
//
//	c2paseal inspect <file>
//	c2paseal verify [--json] [--trust anchors.pem] <file>
//
// Exit codes: 0 = valid (or inspected), 1 = invalid or unreadable, 2 = usage error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

const (
	exitValid   = 0
	exitInvalid = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  c2paseal inspect <file>                              print the manifest store as JSON
  c2paseal verify [--json] [--trust anchors.pem] <file> validate the manifest store

exit codes: 0 valid, 1 invalid or unreadable, 2 usage error`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "inspect":
		return inspect(args[1:], stdout, stderr)
	case "verify":
		return verifyCmd(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		usage(stdout)
		return exitValid
	}
	fmt.Fprintf(stderr, "c2paseal: unknown command %q\n", args[0])
	usage(stderr)
	return exitUsage
}

// parse parses flags that may appear before or after the file argument and
// returns the single positional argument.
func parse(fs *flag.FlagSet, args []string) (string, bool) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return "", false
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 {
		fmt.Fprintf(fs.Output(), "c2paseal %s: want exactly one file, got %d\n", fs.Name(), len(pos))
		return "", false
	}
	return pos[0], true
}

func inspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file, ok := parse(fs, args)
	if !ok {
		return exitUsage
	}
	s, err := c2paseal.Read(file)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitInvalid
	}
	return writeJSON(stdout, stderr, s)
}

func verifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print validation results as JSON")
	trust := fs.String("trust", "", "PEM file of trust anchor certificates")
	file, ok := parse(fs, args)
	if !ok {
		return exitUsage
	}
	opts := &c2paseal.VerifyOptions{}
	if *trust != "" {
		anchors, err := c2paseal.LoadTrustAnchors(*trust)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		opts.TrustAnchors = anchors
	}

	r := c2paseal.VerifyFile(file, opts)
	state := r.State()
	if *asJSON {
		if code := writeJSON(stdout, stderr, struct {
			Results *verify.Result `json:"validation_results"`
			State   verify.State   `json:"validation_state"`
		}{r, state}); code != exitValid {
			return code
		}
	} else {
		printResult(stdout, r)
	}
	if state == verify.Invalid {
		return exitInvalid
	}
	return exitValid
}

func printResult(w io.Writer, r *verify.Result) {
	section := func(statuses []verify.Status) {
		for _, k := range []verify.Kind{verify.Success, verify.Informational, verify.Failure} {
			for _, s := range statuses {
				if s.Kind() == k {
					fmt.Fprintf(w, "  %-13s %s\n", k, s.Code)
					fmt.Fprintf(w, "  %13s %s\n", "", s.Explanation)
				}
			}
		}
	}
	fmt.Fprintln(w, "active manifest:")
	section(r.ActiveManifest)
	for _, d := range r.IngredientDeltas {
		fmt.Fprintf(w, "ingredient %s:\n", d.IngredientAssertionURI)
		section(d.ValidationDeltas)
	}
	fmt.Fprintf(w, "state: %s\n", r.State())
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "c2paseal:", err)
		return exitInvalid
	}
	fmt.Fprintln(stdout, string(b))
	return exitValid
}
