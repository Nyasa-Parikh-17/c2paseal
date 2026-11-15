// Command sealstore is a self-hosted manifest store: it keeps C2PA manifest
// stores by watermark ID, so that a copy of an image whose credentials were
// stripped can get them back.
//
//	sealstore serve   --dir DIR --api-keys FILE [--addr :8090]
//	sealstore sign    --cert chain.pem --key key.pem --in IN --out OUT [--store URL --api-key KEY]
//	sealstore recover --store URL [--trust anchors.pem] [--json] FILE
//	sealstore version
//
// sign watermarks a JPEG or PNG with a new random ID, signs it with a
// c2pa.soft-binding assertion recording that ID, writes it, and with
// --store uploads the manifest store under the ID. recover reads the ID
// from a copy (JPEG, PNG or WebP), fetches the store and verifies the copy
// against it: the signature validates; the hard binding fails when the
// copy was re-encoded, which the report says plainly.
//
// Store API:
//
//	PUT /v1/manifests/{id}   body: the manifest store; needs
//	                         "Authorization: Bearer <API key>"; the store's
//	                         active manifest must record {id} as its
//	                         watermark soft binding
//	GET /v1/manifests/{id}   the store (application/c2pa); public, CORS open
//	GET /healthz
//
// This is its own Go module (it uses the watermark module, which needs
// golang.org/x/image); the core C2paSeal module does not depend on it.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark/wmfile"
)

var version = ""

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  sealstore serve   --dir DIR --api-keys FILE [--addr :8090] [--max-bytes N] [--audit-log FILE]
  sealstore sign    --cert chain.pem --key key.pem --in IN --out OUT [--title T] [--store URL --api-key KEY]
  sealstore recover --store URL [--trust anchors.pem] [--json] FILE
  sealstore version`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stdout, stderr)
	case "sign":
		return signCmd(ctx, args[1:], stdout, stderr)
	case "recover":
		return recoverCmd(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "sealstore %s (%s)\n", buildVersion(), runtime.Version())
		return 0
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "sealstore: unknown command %q\n%s\n", args[0], usage)
	return 2
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("sealstore "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("serve", stderr)
	addr := fs.String("addr", ":8090", "listen address")
	dir := fs.String("dir", "", "directory holding the manifest stores (required)")
	keysPath := fs.String("api-keys", "", "API key file: <name> <sha256 hex> per line, as made by `sealsvc hash-key` (required)")
	maxBytes := fs.Int64("max-bytes", 16<<20, "largest manifest store accepted")
	auditPath := fs.String("audit-log", "", "append JSON audit records to this file (default: stderr)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "sealstore:", err); return 2 }
	if *dir == "" || *keysPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "sealstore serve: --dir and --api-keys are required")
		return 2
	}
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		return fail(fmt.Errorf("--dir %s is not a directory", *dir))
	}
	kf, err := os.Open(*keysPath)
	if err != nil {
		return fail(err)
	}
	keys, err := parseKeys(kf)
	kf.Close()
	if err != nil {
		return fail(err)
	}
	audit := stderr
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		audit = f
	}
	logger := slog.New(slog.NewJSONHandler(audit, nil))
	s := &server{store: &fileStore{dir: *dir}, keys: keys, maxBytes: *maxBytes, audit: logger, version: buildVersion()}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fail(err)
	}
	srv := newHTTPServer(s.handler(), logger)
	logger.Info("start", slog.String("listen", ln.Addr().String()), slog.Int("api_keys", len(keys)), slog.String("version", buildVersion()))
	fmt.Fprintf(stdout, "sealstore listening on http://%s\n", ln.Addr())
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(err)
	}
	logger.Info("stop")
	return 0
}

func signCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("sign", stderr)
	cert := fs.String("cert", "", "PEM certificate chain, signer first (required)")
	keyURI := fs.String("key", "", "signing key: a PEM file or file: URI (required)")
	in := fs.String("in", "", "JPEG or PNG to watermark and sign (required)")
	out := fs.String("out", "", "where to write the result (required)")
	title := fs.String("title", "", "optional dc:title")
	storeURL := fs.String("store", "", "sealstore URL to upload the manifest store to")
	apiKey := fs.String("api-key", os.Getenv("SEALSTORE_API_KEY"), "API key for --store (env SEALSTORE_API_KEY)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(code int, err error) int { fmt.Fprintln(stderr, "sealstore sign:", err); return code }
	if *cert == "" || *keyURI == "" || *in == "" || *out == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "sealstore sign: --cert, --key, --in and --out are required")
		return 2
	}
	if *storeURL != "" && *apiKey == "" {
		return fail(2, errors.New("--store needs --api-key (or SEALSTORE_API_KEY)"))
	}
	chain, err := c2paseal.LoadChain(*cert)
	if err != nil {
		return fail(2, err)
	}
	signer, err := sign.OpenKey(ctx, *keyURI)
	if err != nil {
		return fail(2, err)
	}
	src, err := os.ReadFile(*in)
	if err != nil {
		return fail(2, err)
	}
	res, err := watermarkAndSign(src, &c2paseal.SignOptions{Chain: chain, Signer: signer, Title: *title})
	if err != nil {
		return fail(1, err)
	}
	if err := os.WriteFile(*out, res.file, 0o644); err != nil {
		return fail(1, err)
	}
	uploaded := false
	if *storeURL != "" {
		if err := upload(ctx, http.DefaultClient, *storeURL, *apiKey, res.id, res.store); err != nil {
			return fail(1, fmt.Errorf("upload: %w", err))
		}
		uploaded = true
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"output": *out, "watermark_id": res.id.String(), "active_manifest": res.manifest, "uploaded": uploaded}, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprintf(stdout, "signed %s -> %s with watermark %s\n", *in, *out, res.id)
	if uploaded {
		fmt.Fprintf(stdout, "manifest store uploaded to %s\n", *storeURL)
	}
	return 0
}

type signResult struct {
	id       watermark.ID
	file     []byte
	store    []byte
	manifest string
}

// watermarkAndSign marks src with a new random ID, then signs the marked
// image with a soft binding that records the ID. Watermarking comes first:
// it changes the pixels, which the hard binding covers.
func watermarkAndSign(src []byte, opts *c2paseal.SignOptions) (*signResult, error) {
	id, err := watermark.NewID()
	if err != nil {
		return nil, err
	}
	marked, err := wmfile.EmbedFile(src, id, nil)
	if err != nil {
		return nil, err
	}
	o := *opts
	o.SoftBindings = append(append([]sign.SoftBinding(nil), opts.SoftBindings...), sign.SoftBinding{Alg: watermark.SoftBindingAlg, Value: id.String()})
	signed, err := c2paseal.SignAsset(marked, &o)
	if err != nil {
		return nil, err
	}
	ms, err := c2paseal.ReadStore(signed.Store)
	if err != nil {
		return nil, err
	}
	return &signResult{id: id, file: signed.File, store: signed.Store, manifest: ms.Active.Label}, nil
}

// upload PUTs a manifest store to a sealstore server.
func upload(ctx context.Context, client *http.Client, storeURL, apiKey string, id watermark.ID, store []byte) error {
	u := strings.TrimRight(storeURL, "/") + "/v1/manifests/" + id.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(store))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/c2pa")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("store answered %s: %s", resp.Status, e.Error)
	}
	return nil
}

func recoverCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("recover", stderr)
	storeURL := fs.String("store", os.Getenv("SEALSTORE_URL"), "sealstore URL (env SEALSTORE_URL; required)")
	var trust []string
	fs.Func("trust", "PEM trust anchors, such as the C2PA trust list; repeatable", func(s string) error { trust = append(trust, s); return nil })
	asJSON := fs.Bool("json", false, "print the result as JSON")
	files, code := parseInterspersed(fs, args)
	if code >= 0 {
		return code
	}
	if *storeURL == "" || len(files) != 1 {
		fmt.Fprintln(stderr, "sealstore recover: --store and one file are required")
		return 2
	}
	var anchors []*x509.Certificate
	for _, p := range trust {
		a, err := c2paseal.LoadTrustList(p)
		if err != nil {
			fmt.Fprintln(stderr, "sealstore recover:", err)
			return 2
		}
		anchors = append(anchors, a...)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		fmt.Fprintln(stderr, "sealstore recover:", err)
		return 2
	}
	rc := recoverCredentials(ctx, &http.Client{Timeout: 30 * time.Second}, b, *storeURL, anchors)
	if *asJSON {
		j, _ := json.MarshalIndent(rc, "", "  ")
		fmt.Fprintln(stdout, string(j))
	} else {
		fmt.Fprint(stdout, rc.describe())
	}
	if !rc.Recovered {
		return 1
	}
	return 0
}

// parseInterspersed parses flags that may come before or after the file
// arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, int) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, 0
			}
			return nil, 2
		}
		if fs.NArg() == 0 {
			return pos, -1
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
