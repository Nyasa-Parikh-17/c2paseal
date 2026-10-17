// Command c2paseal inspects, verifies and signs C2PA Content Credentials.
//
// Exit codes: 0 = valid, 1 = invalid, 2 = usage error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	exitValid   = 0
	exitInvalid = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("c2paseal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: c2paseal <command> [flags] <file>")
		fmt.Fprintln(stderr, "commands: inspect, verify, sign (not implemented yet)")
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return exitUsage
	}
	fmt.Fprintf(stderr, "c2paseal: unknown command %q\n", fs.Arg(0))
	fs.Usage()
	return exitUsage
}
