package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// server is sealsvc's HTTP API.
type server struct {
	chain    []*x509.Certificate
	signer   crypto.Signer
	anchors  []*x509.Certificate // for /v1/verify
	tsaURL   string
	maxBytes int64
	keys     *keyring
	audit    *slog.Logger
	metrics  *metrics
	slots    chan struct{} // concurrency limit for sign and verify
	now      func() time.Time
	version  string
}

// handler returns the routes:
//
//	POST /v1/sign     body: a JPEG or PNG; answer: the signed file
//	POST /v1/verify   body: a JPEG or PNG; answer: `c2paseal verify --json`
//	GET  /healthz     liveness, no API key
//	GET  /metrics     Prometheus text format, no API key
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/sign", s.api("sign", scopeSign, s.sign))
	mux.Handle("POST /v1/verify", s.api("verify", scopeVerify, s.verify))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","version":` + strconv.Quote(s.version) + "}\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.metrics.write(w)
	})
	return mux
}

// call is one API request as the audit log records it.
type call struct {
	id       string
	key      *apiKey
	status   int
	errMsg   string // for the log; the client gets a generic message for 5xx
	bytesIn  int64
	bytesOut int64
	attrs    []slog.Attr
}

// api wraps an endpoint with the request ID, API key check, rate limit,
// concurrency limit, body size limit, metrics and audit log.
func (s *server) api(endpoint, scope string, fn func(*call, http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		c := &call{id: requestID()}
		w.Header().Set("X-Request-Id", c.id)
		cw := &countingWriter{ResponseWriter: w}
		defer func() {
			d := s.now().Sub(start)
			s.metrics.observe(endpoint, c.status, d, c.bytesIn, cw.n)
			c.bytesOut = cw.n
			s.log(r, endpoint, c, d)
		}()

		c.key = s.keys.lookup(r)
		switch {
		case c.key == nil:
			s.metrics.add(&s.metrics.authFail)
			w.Header().Set("WWW-Authenticate", `Bearer realm="sealsvc"`)
			s.fail(cw, c, http.StatusUnauthorized, "missing or unknown API key", nil)
			return
		case !c.key.can(scope):
			s.fail(cw, c, http.StatusForbidden, "this API key may not "+scope, nil)
			return
		}
		if ok, wait := c.key.bucket.take(s.now()); !ok {
			s.metrics.addKey(s.metrics.limited, c.key.name)
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			s.fail(cw, c, http.StatusTooManyRequests, "rate limit exceeded", nil)
			return
		}
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			s.metrics.add(&s.metrics.busy)
			w.Header().Set("Retry-After", "1")
			s.fail(cw, c, http.StatusServiceUnavailable, "server busy, retry later", nil)
			return
		}
		s.metrics.flight(1)
		defer s.metrics.flight(-1)

		r.Body = http.MaxBytesReader(cw, r.Body, s.maxBytes)
		if err := fn(c, cw, r); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				s.fail(cw, c, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body over %d bytes", s.maxBytes), err)
				return
			}
			var he *httpError
			if errors.As(err, &he) {
				s.fail(cw, c, he.code, he.msg, he.err)
				return
			}
			s.fail(cw, c, http.StatusInternalServerError, "internal error", err)
		}
	})
}

// httpError is an endpoint error with the status and message for the
// client; err, if set, goes to the audit log only.
type httpError struct {
	code int
	msg  string
	err  error
}

func (e *httpError) Error() string { return e.msg }

// readBody reads the request body (already size-limited).
func readBody(c *call, r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(r.Body)
	c.bytesIn = int64(len(b))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, &httpError{code: http.StatusBadRequest, msg: "empty request body: send the JPEG or PNG as the body"}
	}
	return b, nil
}

func (s *server) sign(c *call, w http.ResponseWriter, r *http.Request) error {
	b, err := readBody(c, r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	noHistory, err := boolParam(q.Get("no_history"))
	if err != nil {
		return &httpError{code: http.StatusBadRequest, msg: "no_history: " + err.Error()}
	}
	format := c2paseal.DetectFormat(b)
	if format != "jpeg" && format != "png" {
		return &httpError{code: http.StatusUnsupportedMediaType, msg: "the body is not a JPEG or PNG"}
	}
	in := sha256.Sum256(b)
	c.attrs = append(c.attrs, slog.String("format", format), slog.String("input_sha256", hex.EncodeToString(in[:])))
	ts := &trackingSigner{Signer: s.signer}
	signed, err := c2paseal.SignAsset(b, &c2paseal.SignOptions{
		Chain: s.chain, Signer: ts, TSAURL: s.tsaURL,
		Title: q.Get("title"), DigitalSourceType: q.Get("source_type"), NoHistory: noHistory,
	})
	if err != nil {
		// The key (a KMS) or the time-stamp authority failing is ours, and
		// the client gets no details; anything else is about the file or
		// the options sent (a broken file, a source type on a signed file).
		if ts.err != nil || errors.Is(err, sign.ErrTimestamp) || errors.Is(err, sign.ErrTimestampTooLarge) {
			return &httpError{code: http.StatusBadGateway, msg: "signing failed", err: err}
		}
		return &httpError{code: http.StatusUnprocessableEntity, msg: err.Error(), err: err}
	}
	store, err := c2paseal.ReadBytes(signed.File)
	if err != nil {
		return err
	}
	out := sha256.Sum256(signed.File)
	c.attrs = append(c.attrs,
		slog.String("output_sha256", hex.EncodeToString(out[:])),
		slog.String("active_manifest", store.Active.Label),
		slog.Int("manifests", len(store.Manifests)))
	s.metrics.addKey(s.metrics.signed, c.key.name)
	ct := "image/jpeg"
	if format == "png" {
		ct = "image/png"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(signed.File)))
	w.Header().Set("C2paseal-Active-Manifest", store.Active.Label)
	w.Header().Set("C2paseal-Manifests", strconv.Itoa(len(store.Manifests)))
	c.status = http.StatusOK
	_, err = w.Write(signed.File)
	if err != nil {
		c.errMsg = "write response: " + err.Error()
	}
	return nil
}

func (s *server) verify(c *call, w http.ResponseWriter, r *http.Request) error {
	b, err := readBody(c, r)
	if err != nil {
		return err
	}
	in := sha256.Sum256(b)
	res := c2paseal.VerifyBytes(b, &c2paseal.VerifyOptions{TrustAnchors: s.anchors})
	state := res.State()
	c.attrs = append(c.attrs, slog.String("input_sha256", hex.EncodeToString(in[:])), slog.String("validation_state", string(state)))
	body, err := json.Marshal(struct {
		Results *verify.Result `json:"validation_results"`
		State   verify.State   `json:"validation_state"`
	}{res, state})
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	c.status = http.StatusOK
	w.Write(body)
	return nil
}

// trackingSigner remembers whether the key failed to sign, so a KMS error
// is told apart from a bad input file.
type trackingSigner struct {
	crypto.Signer
	err error
}

func (t *trackingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := t.Signer.Sign(r, digest, opts)
	if err != nil {
		t.err = err
	}
	return sig, err
}

func boolParam(s string) (bool, error) {
	if s == "" {
		return false, nil
	}
	return strconv.ParseBool(s)
}

// fail answers with {"error": msg, "request_id": id}.
func (s *server) fail(w http.ResponseWriter, c *call, code int, msg string, err error) {
	c.status = code
	c.errMsg = msg
	if err != nil {
		c.errMsg = msg + ": " + err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": msg, "request_id": c.id})
	w.Write(append(b, '\n'))
}

// log writes the audit record for a request. It never contains the API
// key, the Authorization header or file contents: only the key's name and
// the files' SHA-256.
func (s *server) log(r *http.Request, endpoint string, c *call, d time.Duration) {
	attrs := []slog.Attr{
		slog.String("request_id", c.id),
		slog.String("endpoint", endpoint),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote_addr", r.RemoteAddr),
		slog.Int("status", c.status),
		slog.Int64("bytes_in", c.bytesIn),
		slog.Int64("bytes_out", c.bytesOut),
		slog.Float64("duration_ms", float64(d.Microseconds())/1000),
	}
	if c.key != nil {
		attrs = append(attrs, slog.String("api_key", c.key.name))
	}
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		attrs = append(attrs, slog.String("forwarded_for", f))
	}
	if ua := r.UserAgent(); ua != "" {
		attrs = append(attrs, slog.String("user_agent", ua))
	}
	attrs = append(attrs, c.attrs...)
	level := slog.LevelInfo
	if c.errMsg != "" {
		attrs = append(attrs, slog.String("error", c.errMsg))
		if c.status >= 500 {
			level = slog.LevelError
		} else {
			level = slog.LevelWarn
		}
	}
	s.audit.LogAttrs(context.Background(), level, endpoint, attrs...)
}

func requestID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// countingWriter counts response body bytes.
type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}
