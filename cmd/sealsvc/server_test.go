package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/keys/awskms/awskmstest"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// Test API keys and the key file that holds their hashes.
const (
	keyAll    = "sk_test_all_0123456789abcdefghijklmnop"
	keyVerify = "sk_test_verify_0123456789abcdefghijkl"
	keySlow   = "sk_test_slow_0123456789abcdefghijklmno"
)

func hashOf(k string) string { h := sha256.Sum256([]byte(k)); return hex.EncodeToString(h[:]) }

func keyFile() string {
	return "# test keys\n" +
		"ci " + hashOf(keyAll) + "\n" +
		"reader " + hashOf(keyVerify) + " scopes=verify\n" +
		"slow " + hashOf(keySlow) + " rate=2/min\n"
}

func td(t *testing.T, rel string) string { return filepath.Join(signtest.TestdataDir(t), rel) }

func read(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(td(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testServer is a server with the TEST ONLY leaf key, trusting the TEST
// ONLY root, and an audit log in memory.
type testServer struct {
	*server
	url   string
	audit *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newTestServer(t *testing.T, signer crypto.Signer, edit func(*server)) *testServer {
	t.Helper()
	chain, leafKey, err := c2paseal.LoadSigner(td(t, "pki/leaf-chain.pem"), td(t, "pki/leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		signer = leafKey
	}
	anchors, err := c2paseal.LoadTrustAnchors(td(t, "pki/trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseKeyring(strings.NewReader(keyFile()), 600)
	if err != nil {
		t.Fatal(err)
	}
	audit := &syncBuffer{}
	s := &server{
		chain: chain, signer: signer, anchors: anchors, maxBytes: 1 << 20, keys: keys,
		audit: slog.New(slog.NewJSONHandler(audit, nil)), metrics: newMetrics("test", "go"),
		slots: make(chan struct{}, 4), now: time.Now, version: "test",
	}
	if edit != nil {
		edit(s)
	}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return &testServer{server: s, url: srv.URL, audit: audit}
}

// post POSTs body to path with an API key ("" for none).
func post(t *testing.T, url, path, key string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func errorOf(t *testing.T, b []byte) string {
	t.Helper()
	var e struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(b, &e); err != nil || e.Error == "" || len(e.RequestID) != 24 {
		t.Fatalf("not an error answer: %s", b)
	}
	return e.Error
}

func TestSignAndVerify(t *testing.T) {
	s := newTestServer(t, nil, nil)
	for _, name := range []string{"small.jpg", "small.png"} {
		t.Run(name, func(t *testing.T) {
			resp, signed := post(t, s.url, "/v1/sign?title=served", keyAll, read(t, "unsigned/"+name))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("sign: %s: %s", resp.Status, signed)
			}
			wantCT := map[string]string{"small.jpg": "image/jpeg", "small.png": "image/png"}[name]
			if resp.Header.Get("Content-Type") != wantCT || !strings.HasPrefix(resp.Header.Get("C2paseal-Active-Manifest"), "urn:c2pa:") ||
				resp.Header.Get("C2paseal-Manifests") != "1" || len(resp.Header.Get("X-Request-Id")) != 24 {
				t.Errorf("headers: %v", resp.Header)
			}
			out := filepath.Join(t.TempDir(), "served-"+name)
			os.WriteFile(out, signed, 0o644)
			signtest.CheckFile(t, out)

			resp, body := post(t, s.url, "/v1/verify", keyVerify, signed)
			var v struct {
				Results json.RawMessage `json:"validation_results"`
				State   verify.State    `json:"validation_state"`
			}
			if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &v) != nil || v.State != verify.Trusted || v.Results == nil {
				t.Errorf("verify: %s %s", resp.Status, body)
			}

			// Signing the signed file keeps it as the parent; no_history
			// replaces it.
			resp, _ = post(t, s.url, "/v1/sign", keyAll, signed)
			if resp.Header.Get("C2paseal-Manifests") != "2" {
				t.Errorf("re-sign: %s, %s manifests", resp.Status, resp.Header.Get("C2paseal-Manifests"))
			}
			resp, _ = post(t, s.url, "/v1/sign?no_history=1", keyAll, signed)
			if resp.Header.Get("C2paseal-Manifests") != "1" {
				t.Errorf("no_history: %s, %s manifests", resp.Status, resp.Header.Get("C2paseal-Manifests"))
			}
		})
	}
}

// TestKMSEndToEnd is the phase's check: the sealsvc program, started as in
// production with an awskms: key URI (here a fake KMS), signs over HTTP,
// and the result verifies in C2paSeal and in c2patool.
func TestKMSEndToEnd(t *testing.T) {
	awskmstest.Isolate(t)
	kms := awskmstest.NewServer(t)
	dir := t.TempDir()
	var chainPEM []byte
	for _, c := range signtest.Chain(t, kms.Key.Public()) {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	args := []string{
		"--addr", "127.0.0.1:0", "--cert", write("chain.pem", string(chainPEM)), "--key", kms.URI(),
		"--api-keys", write("keys.txt", keyFile()), "--trust", td(t, "pki/trust-anchors.pem"), "--audit-log", auditPath,
	}
	ctx, cancel := context.WithCancel(t.Context())
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	var stderr bytes.Buffer
	go func() { done <- run(ctx, args, pw, &stderr); pw.Close() }()
	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		t.Fatalf("no listening line: %v; stderr: %s", err, stderr.String())
	}
	go io.Copy(io.Discard, pr)
	url := strings.TrimSpace(strings.TrimPrefix(line, "sealsvc listening on "))

	for _, name := range []string{"small.jpg", "small.png"} {
		resp, signed := post(t, url, "/v1/sign", keyAll, read(t, "unsigned/"+name))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %s: %s", name, resp.Status, signed)
		}
		out := filepath.Join(t.TempDir(), "kms-"+name)
		os.WriteFile(out, signed, 0o644)
		signtest.CheckFile(t, out)
		resp, body := post(t, url, "/v1/verify", keyAll, signed)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"validation_state":"Trusted"`) {
			t.Errorf("%s verify: %s %s", name, resp.Status, body)
		}
	}
	if kms.Calls("Sign") != 2 || kms.Calls("GetPublicKey") != 1 {
		t.Errorf("KMS calls: %d Sign, %d GetPublicKey", kms.Calls("Sign"), kms.Calls("GetPublicKey"))
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run exited %d: %s", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not stop")
	}
	log, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(log), `"msg":"start"`) || !strings.Contains(string(log), `"key":"awskms:`+awskmstest.ARN+`"`) ||
		strings.Contains(string(log), kms.URL) || !strings.Contains(string(log), `"msg":"stop"`) {
		t.Errorf("audit log: start record should name the key without its endpoint:\n%s", log)
	}
}

func TestAuthAndLimits(t *testing.T) {
	s := newTestServer(t, nil, func(s *server) { s.maxBytes = 64 << 10 })
	img := read(t, "unsigned/small.jpg")
	for _, tc := range []struct {
		name, path, key string
		body            []byte
		code            int
		msg             string
	}{
		{"no key", "/v1/sign", "", img, 401, "missing or unknown API key"},
		{"unknown key", "/v1/sign", "sk_nope", img, 401, "missing or unknown API key"},
		{"verify-only key signs", "/v1/sign", keyVerify, img, 403, "may not sign"},
		{"too large", "/v1/verify", keyAll, make([]byte, 65<<10), 413, "request body over 65536 bytes"},
		{"empty", "/v1/sign", keyAll, nil, 400, "empty request body"},
		{"not an image", "/v1/sign", keyAll, []byte("hello"), 415, "not a JPEG or PNG"},
		{"bad no_history", "/v1/sign?no_history=maybe", keyAll, img, 400, "no_history"},
		{"source type on a signed file", "/v1/sign?source_type=x", keyAll, read(t, "signed/small.jpg"), 422, ""},
		{"broken JPEG", "/v1/sign", keyAll, read(t, "broken/truncated-app11.jpg"), 422, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := post(t, s.url, tc.path, tc.key, tc.body)
			if resp.StatusCode != tc.code || !strings.Contains(errorOf(t, body), tc.msg) {
				t.Errorf("%s: %s", resp.Status, body)
			}
			if tc.code == 401 && resp.Header.Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate")
			}
		})
	}
	// Malformed files are verify results, not errors.
	if resp, body := post(t, s.url, "/v1/verify", keyAll, []byte("hello")); resp.StatusCode != 200 || !strings.Contains(string(body), `"Invalid"`) {
		t.Errorf("verify garbage: %s %s", resp.Status, body)
	}
	// Other methods and paths.
	if r, _ := http.Get(s.url + "/v1/sign"); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/sign: %s", r.Status)
	}
	if r, _ := http.Get(s.url + "/v2/sign"); r.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v2/sign: %s", r.Status)
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s := newTestServer(t, nil, func(s *server) {
		s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	img := read(t, "signed/small.jpg")
	for i := range 2 { // slow: 2/min, burst 2
		if resp, b := post(t, s.url, "/v1/verify", keySlow, img); resp.StatusCode != 200 {
			t.Fatalf("request %d: %s %s", i, resp.Status, b)
		}
	}
	resp, body := post(t, s.url, "/v1/verify", keySlow, img)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "31" || !strings.Contains(errorOf(t, body), "rate limit") {
		t.Errorf("third request: %s, Retry-After %q", resp.Status, resp.Header.Get("Retry-After"))
	}
	// Other keys are not affected; after 30 s one more token is there.
	if resp, _ := post(t, s.url, "/v1/verify", keyAll, img); resp.StatusCode != 200 {
		t.Errorf("other key: %s", resp.Status)
	}
	mu.Lock()
	now = now.Add(30 * time.Second)
	mu.Unlock()
	if resp, _ := post(t, s.url, "/v1/verify", keySlow, img); resp.StatusCode != 200 {
		t.Errorf("after 30 s: %s", resp.Status)
	}
	if !strings.Contains(metricsText(t, s.url), `sealsvc_rate_limited_total{key="slow"} 1`) {
		t.Error("rate-limited request not counted")
	}
}

// blockingSigner signs after release is closed, or fails.
type blockingSigner struct {
	crypto.Signer
	entered chan struct{}
	release chan struct{}
	fail    bool
}

func (b *blockingSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if b.entered != nil {
		b.entered <- struct{}{}
		<-b.release
	}
	if b.fail {
		return nil, errors.New("kms: AccessDeniedException: arn:aws:kms:secret-account")
	}
	return b.Signer.Sign(r, d, o)
}

func TestBusyAndSignerFailure(t *testing.T) {
	leaf, err := sign.OpenKey(t.Context(), td(t, "pki/leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	bs := &blockingSigner{Signer: leaf, entered: make(chan struct{}), release: make(chan struct{})}
	s := newTestServer(t, bs, func(s *server) { s.slots = make(chan struct{}, 1) })
	img := read(t, "unsigned/small.jpg")
	first := make(chan int)
	go func() { resp, _ := post(t, s.url, "/v1/sign", keyAll, img); first <- resp.StatusCode }()
	<-bs.entered // the first request holds the only slot
	resp, body := post(t, s.url, "/v1/verify", keyAll, img)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" || !strings.Contains(errorOf(t, body), "busy") {
		t.Errorf("second request: %s %s", resp.Status, body)
	}
	close(bs.release)
	if code := <-first; code != 200 {
		t.Errorf("first request: %d", code)
	}

	// The key failing is a 502 with no details for the client; the audit
	// log has them.
	bs.entered, bs.fail = nil, true
	resp, body = post(t, s.url, "/v1/sign", keyAll, img)
	if resp.StatusCode != 502 || errorOf(t, body) != "signing failed" {
		t.Errorf("signer failure: %s %s", resp.Status, body)
	}
	if !strings.Contains(s.audit.String(), "AccessDeniedException") {
		t.Error("audit log lacks the signer error")
	}
}

func metricsText(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Errorf("metrics Content-Type %q", resp.Header.Get("Content-Type"))
	}
	return string(b)
}

// sample matches one exposition-format sample line.
var sample = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*",?)*\})? -?[0-9.e+]+$`)

func TestMetricsAndHealth(t *testing.T) {
	s := newTestServer(t, nil, nil)
	img := read(t, "unsigned/small.png")
	post(t, s.url, "/v1/sign", keyAll, img)
	post(t, s.url, "/v1/sign", "", img)
	post(t, s.url, "/v1/verify", keyVerify, img)
	m := metricsText(t, s.url)
	for _, want := range []string{
		`sealsvc_build_info{version="test",goversion="go"} 1`,
		`sealsvc_requests_total{endpoint="sign",code="200"} 1`,
		`sealsvc_requests_total{endpoint="sign",code="401"} 1`,
		`sealsvc_requests_total{endpoint="verify",code="200"} 1`,
		`sealsvc_signatures_total{key="ci"} 1`,
		`sealsvc_auth_failures_total 1`,
		`sealsvc_request_duration_seconds_count{endpoint="sign"} 2`,
		`sealsvc_request_duration_seconds_bucket{endpoint="sign",le="+Inf"} 2`,
		`sealsvc_request_bytes_total{endpoint="sign"} ` + itoa(len(img)), // the 401 body is never read
		`sealsvc_in_flight_requests 0`,
	} {
		if !strings.Contains(m, want+"\n") {
			t.Errorf("metrics lack %q", want)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(m), "\n") {
		if !strings.HasPrefix(line, "# ") && !sample.MatchString(line) {
			t.Errorf("not an exposition-format sample: %q", line)
		}
	}
	resp, err := http.Get(s.url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != `{"status":"ok","version":"test"}`+"\n" {
		t.Errorf("healthz: %s %s", resp.Status, b)
	}
	if quote("a\"b\\c\nd") != `"a\"b\\c\nd"` {
		t.Errorf("quote: %s", quote("a\"b\\c\nd"))
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestAuditLog checks the audit record of a sign request, and that no
// record holds an API key, the Authorization header or file bytes.
func TestAuditLog(t *testing.T) {
	s := newTestServer(t, nil, nil)
	img := read(t, "unsigned/small.jpg")
	req, _ := http.NewRequest(http.MethodPost, s.url+"/v1/sign", bytes.NewReader(img))
	req.Header.Set("Authorization", "Bearer "+keyAll)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("User-Agent", "audit-test/1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	post(t, s.url, "/v1/verify", "sk_wrong_key_value", img)

	lines := strings.Split(strings.TrimSpace(s.audit.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d audit records, want 2:\n%s", len(lines), s.audit.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	inHash, outHash := sha256.Sum256(img), sha256.Sum256(signed)
	for k, want := range map[string]any{
		"level": "INFO", "msg": "sign", "endpoint": "sign", "method": "POST", "path": "/v1/sign", "status": float64(200),
		"api_key": "ci", "forwarded_for": "203.0.113.7", "user_agent": "audit-test/1", "format": "jpeg",
		"input_sha256": hex.EncodeToString(inHash[:]), "output_sha256": hex.EncodeToString(outHash[:]),
		"bytes_in": float64(len(img)), "bytes_out": float64(len(signed)), "manifests": float64(1),
		"request_id": resp.Header.Get("X-Request-Id"), "active_manifest": resp.Header.Get("C2paseal-Active-Manifest"),
	} {
		if rec[k] != want {
			t.Errorf("audit %s = %v, want %v", k, rec[k], want)
		}
	}
	for _, k := range []string{"time", "remote_addr", "duration_ms"} {
		if rec[k] == nil {
			t.Errorf("audit record has no %s", k)
		}
	}
	if !strings.Contains(lines[1], `"level":"WARN"`) || !strings.Contains(lines[1], `"status":401`) || strings.Contains(lines[1], `"api_key"`) {
		t.Errorf("401 record: %s", lines[1])
	}
	all := s.audit.String()
	for _, secret := range []string{keyAll, "sk_wrong_key_value", "Bearer", hashOf(keyAll)} {
		if strings.Contains(all, secret) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	t.Logf("audit record sample: %s", lines[0])
}

func TestKeyring(t *testing.T) {
	h := hashOf("x")
	for _, tc := range []struct{ in, want string }{
		{"", "no keys"},
		{"# only a comment\n", "no keys"},
		{"onlyname\n", "want <name> <sha256 hex>"},
		{"a nothex\n", "not a SHA-256 hex digest"},
		{"a " + h + "\na " + h + "\n", "duplicate name"},
		{"a " + h + " rate=fast\n", "want <n>/min"},
		{"a " + h + " rate=0/min\n", "want <n>/min"},
		{"a " + h + " rate=5/h\n", "want <n>/min"},
		{"a " + h + " scopes=sign,admin\n", "unknown scope"},
		{"a " + h + " colour=blue\n", "unknown option"},
	} {
		if _, err := parseKeyring(strings.NewReader(tc.in), 60); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.in, err, tc.want)
		}
	}
	kr, err := parseKeyring(strings.NewReader("a "+h+" rate=2/s scopes=verify\n"), 60)
	if err != nil || kr.keys[0].perMin != 120 || kr.keys[0].can(scopeSign) || !kr.keys[0].can(scopeVerify) {
		t.Errorf("parse: %v %+v", err, kr)
	}
}

func TestBucket(t *testing.T) {
	b := newBucket(0.5) // one request every 2 minutes, burst 1
	t0 := time.Unix(0, 0)
	if ok, _ := b.take(t0); !ok {
		t.Fatal("first take refused")
	}
	ok, wait := b.take(t0.Add(time.Minute))
	if ok || wait != time.Minute {
		t.Errorf("second take after 1 min: %v, wait %v; want refused, 1m0s", ok, wait)
	}
	if ok, _ := b.take(t0.Add(2 * time.Minute)); !ok {
		t.Error("take after 2 min refused")
	}
}

func TestSubcommands(t *testing.T) {
	ctx := t.Context()
	var out, errb bytes.Buffer
	if code := run(ctx, []string{"hash-key"}, &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	m := regexp.MustCompile(`API key .*: (sk_[A-Za-z0-9_-]{43})\nline for the API key file:  <name> ([0-9a-f]{64})\n`).FindStringSubmatch(out.String())
	if m == nil || hashOf(m[1]) != m[2] {
		t.Fatalf("hash-key output: %q", out.String())
	}
	out.Reset()
	if code := run(ctx, []string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "sealsvc ") {
		t.Errorf("version: %d %q", code, out.String())
	}

	s := newTestServer(t, nil, nil)
	out.Reset()
	if code := run(ctx, []string{"healthcheck", "--url", s.url + "/healthz"}, &out, &errb); code != 0 || out.String() != "ok\n" {
		t.Errorf("healthcheck: %d %q %q", code, out.String(), errb.String())
	}
	if code := run(ctx, []string{"healthcheck", "--url", s.url + "/nope"}, io.Discard, io.Discard); code != 1 {
		t.Errorf("healthcheck of a 404: %d", code)
	}

	// Configuration errors stop the server before it listens.
	keys := filepath.Join(t.TempDir(), "keys.txt")
	os.WriteFile(keys, []byte(keyFile()), 0o600)
	otherKey := filepath.Join(t.TempDir(), "other.key")
	os.WriteFile(otherKey, read(t, "pki/intermediate.key"), 0o600)
	base := []string{"--addr", "127.0.0.1:0", "--cert", td(t, "pki/leaf-chain.pem"), "--api-keys", keys}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--addr", "127.0.0.1:0"}, "are required"},
		{append(base, "--key", otherKey), "does not match the certificate"},
		{append(base, "--key", "awskms:alias/x?endpoint=http://127.0.0.1:1&region=eu-west-1"), "awskms"},
		{append(base, "--key", td(t, "pki/leaf.key"), "--rate", "lots"), "want <n>/min"},
		{append(base, "--key", td(t, "pki/leaf.key"), "--tls-cert", "x.pem"), "go together"},
		{append(base, "--key", td(t, "pki/leaf.key"), "--max-bytes", "0"), "must be positive"},
		{append(base, "--key", td(t, "pki/leaf.key"), "--trust", "missing.pem"), "trust anchors"},
	} {
		errb.Reset()
		if code := run(ctx, tc.args, io.Discard, &errb); code != 2 || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: exit %d, %q; want 2 and %q", tc.args, code, errb.String(), tc.want)
		}
	}
	if got := redactURI("awskms:alias/x?endpoint=http://h&profile=p"); got != "awskms:alias/x" {
		t.Errorf("redactURI = %q", got)
	}
	if got := redactURI(`C:\keys\k.pem`); got != `C:\keys\k.pem` {
		t.Errorf("redactURI(path) = %q", got)
	}
}
