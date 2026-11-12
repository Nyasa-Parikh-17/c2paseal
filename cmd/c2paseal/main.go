// Command c2paseal inspects, verifies and signs C2PA Content Credentials in
// JPEG and PNG files, and serves a demo UI.
//
//	c2paseal inspect [--json] <file>
//	c2paseal verify  [--json] [--trust anchors.pem] <file>
//	c2paseal sign    [--json] --cert chain.pem --key key.pem --in in --out out [--title t] [--source-type uri] [--tsa url]
//	c2paseal serve   [--addr 127.0.0.1:8080] [--pki testdata/pki]
//	c2paseal version [--json]
//
// Every command accepts -h. With --json, results and errors are JSON on
// stdout ({"error": "..."} for errors).
//
// Exit codes: 0 = success / valid manifest; 1 = invalid manifest, unreadable
// file or failed operation; 2 = usage error, including option files (trust
// anchors, certificate, key, PKI directory) that cannot be loaded.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
	"github.com/Nyasa-Parikh-17/c2paseal/web"
)

const (
	exitValid   = 0
	exitInvalid = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = `c2paseal reads, verifies and signs C2PA Content Credentials in JPEG and PNG files.

usage:
  c2paseal inspect [--json] <file>
        print the manifest store as JSON (as c2patool --detailed does)
  c2paseal verify [--json] [--trust anchors.pem] <file>
        validate the manifest store and print the C2PA status codes
  c2paseal sign [--json] --cert chain.pem --key key.pem --in in --out out
                [--title t] [--source-type uri] [--tsa url]
        sign a JPEG or PNG (replaces any existing manifest store)
  c2paseal serve [--addr 127.0.0.1:8080] [--pki testdata/pki]
        run the demo UI in a browser (signs with the TEST ONLY PKI)
  c2paseal version [--json]
        print the version

Run "c2paseal <command> -h" for a command's flags.

exit codes:
  0  success, or the manifest is valid
  1  the manifest is invalid, the file cannot be read, or the operation failed
  2  usage error, or an option file (anchors, certificate, key, PKI) cannot be loaded`

func usage(w io.Writer) { fmt.Fprintln(w, usageText) }

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
	case "sign":
		return signCmd(args[1:], stdout, stderr)
	case "serve":
		return serveCmd(context.Background(), args[1:], stdout, stderr)
	case "version":
		return versionCmd(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		usage(stdout)
		return exitValid
	}
	fmt.Fprintf(stderr, "c2paseal: unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

// command is a sub-command's flag set plus its --json flag.
type command struct {
	fs     *flag.FlagSet
	asJSON *bool
	stdout io.Writer
	stderr io.Writer
}

func newCommand(name, synopsis string, stdout, stderr io.Writer) *command {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: c2paseal %s %s\n\nflags:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return &command{fs: fs, stdout: stdout, stderr: stderr}
}

func (c *command) withJSON(help string) *command {
	c.asJSON = c.fs.Bool("json", false, help)
	return c
}

// parseErr maps a flag parse error to an exit code: -h is success.
func (c *command) parseErr(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitValid
	}
	return exitUsage
}

// fail reports err as {"error": ...} on stdout with --json, else on stderr.
func (c *command) fail(code int, err error) int {
	if c.asJSON != nil && *c.asJSON {
		writeJSON(c.stdout, c.stderr, map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintln(c.stderr, err)
	}
	return code
}

// parseFile parses flags that may appear before or after the single file
// argument and returns it.
func (c *command) parseFile(args []string) (string, int) {
	var pos []string
	for {
		if err := c.fs.Parse(args); err != nil {
			return "", c.parseErr(err)
		}
		if c.fs.NArg() == 0 {
			break
		}
		pos = append(pos, c.fs.Arg(0))
		args = c.fs.Args()[1:]
	}
	if len(pos) != 1 {
		fmt.Fprintf(c.stderr, "c2paseal %s: want exactly one file, got %d\n", c.fs.Name(), len(pos))
		c.fs.Usage()
		return "", exitUsage
	}
	return pos[0], -1
}

func inspect(args []string, stdout, stderr io.Writer) int {
	c := newCommand("inspect", "[--json] <file>", stdout, stderr).
		withJSON("accepted for consistency; inspect always prints JSON")
	file, code := c.parseFile(args)
	if code >= 0 {
		return code
	}
	*c.asJSON = true // errors as JSON too
	s, err := c2paseal.Read(file)
	if err != nil {
		return c.fail(exitInvalid, err)
	}
	return writeJSON(stdout, stderr, s)
}

func verifyCmd(args []string, stdout, stderr io.Writer) int {
	c := newCommand("verify", "[--json] [--trust anchors.pem] <file>", stdout, stderr).
		withJSON("print validation results as JSON")
	trust := c.fs.String("trust", "", "PEM file of trust anchor certificates (default: none, so every signer is untrusted)")
	file, code := c.parseFile(args)
	if code >= 0 {
		return code
	}
	opts := &c2paseal.VerifyOptions{}
	if *trust != "" {
		anchors, err := c2paseal.LoadTrustAnchors(*trust)
		if err != nil {
			return c.fail(exitUsage, err)
		}
		opts.TrustAnchors = anchors
	}

	r := c2paseal.VerifyFile(file, opts)
	state := r.State()
	if *c.asJSON {
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

func signCmd(args []string, stdout, stderr io.Writer) int {
	c := newCommand("sign", "[--json] --cert chain.pem --key key.pem --in in --out out [flags]", stdout, stderr).
		withJSON("print the result as JSON")
	cert := c.fs.String("cert", "", "PEM certificate chain: signer first, then intermediates (required)")
	key := c.fs.String("key", "", "PEM private key of the signer, ECDSA P-256 (required)")
	in := c.fs.String("in", "", "JPEG or PNG to sign (required)")
	out := c.fs.String("out", "", "where to write the signed file (required)")
	title := c.fs.String("title", "", "optional dc:title for the claim")
	tsa := c.fs.String("tsa", "", "RFC 3161 time-stamp authority URL; time-stamps the signature (needs network)")
	source := c.fs.String("source-type", "", "IPTC digital source type for the c2pa.created action (default "+sign.DefaultDigitalSourceType+")")
	if err := c.fs.Parse(args); err != nil {
		return c.parseErr(err)
	}
	if c.fs.NArg() != 0 || *cert == "" || *key == "" || *in == "" || *out == "" {
		fmt.Fprintln(stderr, "c2paseal sign: --cert, --key, --in and --out are required")
		c.fs.Usage()
		return exitUsage
	}
	chain, signer, err := c2paseal.LoadSigner(*cert, *key)
	if err != nil {
		return c.fail(exitUsage, err)
	}
	opts := &c2paseal.SignOptions{Chain: chain, Signer: signer, Title: *title, DigitalSourceType: *source, TSAURL: *tsa}
	if err := c2paseal.Sign(*in, *out, opts); err != nil {
		return c.fail(exitInvalid, err)
	}
	if !*c.asJSON {
		fmt.Fprintf(stdout, "signed %s -> %s\n", *in, *out)
		return exitValid
	}
	s, err := c2paseal.Read(*out)
	if err != nil {
		return c.fail(exitInvalid, err)
	}
	return writeJSON(stdout, stderr, map[string]any{
		"input": *in, "output": *out, "format": s.Format,
		"active_manifest": s.Active.Label, "time_stamped": *tsa != "",
	})
}

// serveCmd runs the demo UI until ctx is done or the process is interrupted.
func serveCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c := newCommand("serve", "[--addr 127.0.0.1:8080] [--pki testdata/pki]", stdout, stderr)
	addr := c.fs.String("addr", "127.0.0.1:8080", "address to listen on (use :8080 to accept connections from other machines)")
	pki := c.fs.String("pki", "testdata/pki", "TEST ONLY PKI directory: leaf-chain.pem, leaf.key, trust-anchors.pem")
	if err := c.fs.Parse(args); err != nil {
		return c.parseErr(err)
	}
	if c.fs.NArg() != 0 {
		c.fs.Usage()
		return exitUsage
	}
	cfg, err := web.LoadTestPKI(*pki)
	if err != nil {
		return c.fail(exitUsage, fmt.Errorf("c2paseal serve: load test PKI from %s: %w (run from the repository root or pass --pki)", *pki, err))
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return c.fail(exitInvalid, fmt.Errorf("c2paseal serve: %w (is the port in use? pick another with --addr 127.0.0.1:8090)", err))
	}
	srv := &http.Server{
		Handler:           web.Handler(cfg),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	fmt.Fprintf(stdout, "C2paSeal demo on http://%s/ (signing with the TEST ONLY PKI in %s; Ctrl+C to stop)\n", ln.Addr(), *pki)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return c.fail(exitInvalid, fmt.Errorf("c2paseal serve: %w", err))
	}
	return exitValid
}

func versionCmd(args []string, stdout, stderr io.Writer) int {
	c := newCommand("version", "[--json]", stdout, stderr).withJSON("print the version as JSON")
	if err := c.fs.Parse(args); err != nil {
		return c.parseErr(err)
	}
	version, goVersion := "(devel)", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion
		if bi.Main.Version != "" {
			version = bi.Main.Version
		}
	}
	if *c.asJSON {
		return writeJSON(stdout, stderr, map[string]string{"version": version, "go": goVersion})
	}
	fmt.Fprintf(stdout, "c2paseal %s (%s)\n", version, goVersion)
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
