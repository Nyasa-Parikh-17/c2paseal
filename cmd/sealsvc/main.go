// Command sealsvc is a self-hosted C2PA signing service over the C2paSeal
// library.
//
//	sealsvc --cert chain.pem --key <key URI> --api-keys keys.txt [flags]
//	sealsvc hash-key        print a new API key and its line for keys.txt
//	sealsvc healthcheck     GET /healthz on the local server (for containers)
//	sealsvc version
//
// The signing key is a key URI (see sign.OpenKey): a PEM file, file:…,
// awskms:… (AWS KMS) or gcpkms:… (Google Cloud KMS). Clients authenticate
// with "Authorization: Bearer <API key>"; the key file stores only the
// keys' SHA-256 hashes.
//
// API:
//
//	POST /v1/sign     body: a JPEG or PNG → the signed file
//	                  query: title, source_type, no_history=1
//	                  headers: C2paseal-Active-Manifest, C2paseal-Manifests
//	POST /v1/verify   body: a JPEG or PNG → JSON as `c2paseal verify --json`
//	GET  /healthz     {"status":"ok"}, no API key
//	GET  /metrics     Prometheus text format, no API key
//
// Errors are JSON: {"error": "...", "request_id": "..."}. Each sign and
// verify request writes one JSON audit record (log/slog) with the API key's
// name, the status, sizes, timing and the SHA-256 of the files; never keys
// or file contents.
//
// This is its own Go module, so the KMS SDKs it links are not
// dependencies of the core C2paSeal module.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"

	_ "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms" // awskms: key URIs
	_ "github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms" // gcpkms: key URIs
)

// version is set at build time with -ldflags "-X main.version=…".
var version = ""

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "hash-key":
			key, hash, err := newAPIKey()
			if err != nil {
				fmt.Fprintln(stderr, "sealsvc:", err)
				return 1
			}
			fmt.Fprintf(stdout, "API key (give it to the client; it is not stored): %s\nline for the API key file:  <name> %s\n", key, hash)
			return 0
		case "healthcheck":
			return healthcheck(args[1:], stdout, stderr)
		case "version":
			fmt.Fprintf(stdout, "sealsvc %s (%s)\n", buildVersion(), runtime.Version())
			return 0
		}
	}
	return serve(ctx, args, stdout, stderr)
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sealsvc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", envOr("SEALSVC_ADDR", ":8080"), "listen address (env SEALSVC_ADDR)")
	certPath := fs.String("cert", os.Getenv("SEALSVC_CERT"), "PEM certificate chain of the signing key, signer first (env SEALSVC_CERT; required)")
	keyURI := fs.String("key", os.Getenv("SEALSVC_KEY"), "signing key: a PEM file or key URI (file:, awskms:, gcpkms:) (env SEALSVC_KEY; required)")
	keysPath := fs.String("api-keys", os.Getenv("SEALSVC_API_KEYS"), "API key file: <name> <sha256 hex> [rate=N/min] [scopes=sign,verify] per line (env SEALSVC_API_KEYS; required)")
	rate := fs.String("rate", "60/min", "default per-key rate limit, <n>/min or <n>/s")
	var trust stringList
	fs.Var(&trust, "trust", "PEM trust anchors for /v1/verify, such as the C2PA trust list; repeatable")
	tsa := fs.String("tsa", "", "RFC 3161 time-stamp authority URL; time-stamps every signature")
	maxBytes := fs.Int64("max-bytes", 32<<20, "largest request body accepted")
	maxConc := fs.Int("max-concurrent", 2*runtime.GOMAXPROCS(0), "sign and verify requests processed at once; more get 503")
	auditPath := fs.String("audit-log", "", "append JSON audit records to this file (default: stderr)")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with this certificate (PEM); without it, put sealsvc behind a TLS proxy")
	tlsKey := fs.String("tls-key", "", "private key for --tls-cert")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "sealsvc:", err); return 2 }
	if fs.NArg() != 0 || *certPath == "" || *keyURI == "" || *keysPath == "" {
		fmt.Fprintln(stderr, "sealsvc: --cert, --key and --api-keys are required")
		fs.Usage()
		return 2
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return fail(errors.New("--tls-cert and --tls-key go together"))
	}
	if *maxBytes <= 0 || *maxConc <= 0 {
		return fail(errors.New("--max-bytes and --max-concurrent must be positive"))
	}
	defRate, err := parseRate(*rate)
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

	chain, err := c2paseal.LoadChain(*certPath)
	if err != nil {
		return fail(err)
	}
	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	signer, err := sign.OpenKey(openCtx, *keyURI)
	cancel()
	if err != nil {
		return fail(err)
	}
	if c, ok := signer.(io.Closer); ok {
		defer c.Close()
	}
	if pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(signer.Public()) {
		return fail(fmt.Errorf("the key %s does not match the certificate in %s", redactURI(*keyURI), *certPath))
	}
	kf, err := os.Open(*keysPath)
	if err != nil {
		return fail(err)
	}
	keys, err := parseKeyring(kf, defRate)
	kf.Close()
	if err != nil {
		return fail(err)
	}
	var anchors []*x509.Certificate
	for _, p := range trust {
		a, err := c2paseal.LoadTrustList(p)
		if err != nil {
			return fail(err)
		}
		anchors = append(anchors, a...)
	}

	s := &server{
		chain: chain, signer: signer, anchors: anchors, tsaURL: *tsa,
		maxBytes: *maxBytes, keys: keys, audit: logger,
		metrics: newMetrics(buildVersion(), runtime.Version()),
		slots:   make(chan struct{}, *maxConc), now: time.Now, version: buildVersion(),
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fail(err)
	}
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	fp := sha256.Sum256(chain[0].Raw)
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	logger.Info("start",
		slog.String("version", buildVersion()),
		slog.String("listen", scheme+"://"+ln.Addr().String()),
		slog.String("key", redactURI(*keyURI)),
		slog.String("signer", chain[0].Subject.String()),
		slog.String("signer_sha256", hex.EncodeToString(fp[:])),
		slog.Time("signer_not_after", chain[0].NotAfter),
		slog.Int("api_keys", len(keys.keys)),
		slog.Int("trust_anchors", len(anchors)),
		slog.Bool("time_stamped", *tsa != ""))
	fmt.Fprintf(stdout, "sealsvc listening on %s://%s\n", scheme, ln.Addr())

	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	if *tlsCert != "" {
		err = srv.ServeTLS(ln, *tlsCert, *tlsKey)
	} else {
		err = srv.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(err)
	}
	logger.Info("stop")
	return 0
}

// healthcheck asks the local server's /healthz and exits 0 if it answers
// 200; distroless images have no curl.
func healthcheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	u := fs.String("url", envOr("SEALSVC_HEALTH_URL", "http://127.0.0.1:8080/healthz"), "health URL (env SEALSVC_HEALTH_URL)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(*u)
	if err != nil {
		fmt.Fprintln(stderr, "sealsvc healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "sealsvc healthcheck:", resp.Status)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

// redactURI drops a key URI's user info and query (which may carry
// endpoints or credentials) for logs.
func redactURI(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || len(u.Scheme) == 1 {
		return s // a path
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}
