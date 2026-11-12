package sign

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/testtsa"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
	"github.com/digitorus/timestamp"
)

// newFakeTSA starts an offline time-stamp authority issued by the test root.
func newFakeTSA(t *testing.T) (*testtsa.TSA, *httptest.Server) {
	t.Helper()
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := testtsa.New(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// TestTimestampHeaderSize: whatever the token's length up to the reserve,
// the unprotected header encodes to exactly the reserved size; one byte more
// is ErrTimestampTooLarge.
func TestTimestampHeaderSize(t *testing.T) {
	for _, reserve := range []int{0, 1, 23, 24, 255, 256, 300, DefaultTimestampReserve, MaxTimestampReserve} {
		size, err := tstHeaderSize(reserve, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{0, 1, 23, 24, 25, 255, 256, 257, 1000, 65535, reserve - 1, reserve} {
			if n < 0 || n > reserve {
				continue
			}
			h, err := tstHeader(make([]byte, n), size, nil)
			if err != nil {
				t.Fatalf("reserve %d, token %d: %v", reserve, n, err)
			}
			b, _ := cbormode.Enc.Marshal(h)
			if len(b) != size {
				t.Fatalf("reserve %d, token %d: header %d bytes, want %d", reserve, n, len(b), size)
			}
		}
		if _, err := tstHeader(make([]byte, reserve+1), size, nil); !errors.Is(err, ErrTimestampTooLarge) {
			t.Errorf("reserve %d: token of reserve+1 bytes: err = %v, want ErrTimestampTooLarge", reserve, err)
		}
	}
	if h, err := tstHeader(nil, 0, nil); err != nil || len(h) != 0 {
		t.Errorf("no time-stamp: header %v, %v; want empty", h, err)
	}
}

// TestTimestampedJPEG: time-stamped signatures verify, the verifier takes
// the signing time from the token (so a signer that has expired since still
// counts), and the store has the same size whatever the token's size.
func TestTimestampedJPEG(t *testing.T) {
	chain, key := testPKI(t)
	tsa, srv := newFakeTSA(t)
	stampTime := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	tsa.At = func() time.Time { return stampTime }
	afterExpiry := func() time.Time { return chain[0].NotAfter.AddDate(1, 0, 0) }

	for _, f := range unsignedJPEGs(t) {
		in, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := JPEG(in, &Options{Chain: chain, Signer: key})
		if err != nil {
			t.Fatal(err)
		}
		var lengths []int
		for _, serialLen := range []int{1, 8, 20} { // tokens of different sizes
			tsa.SerialLen = serialLen
			out, err := JPEG(in, &Options{Chain: chain, Signer: key, TSAURL: srv.URL})
			if err != nil {
				t.Fatalf("%s: %v", f.Name, err)
			}
			lengths = append(lengths, len(out))

			// Trusted root, checked a year after the signer expired: the
			// trusted time-stamp's time is used, so no failures.
			r := verify.File(out, &verify.Options{TrustAnchors: anchors(t), Now: afterExpiry})
			codes := statusCodes(r)
			if got := failures(r); len(got) != 0 || r.State() != verify.Trusted {
				t.Errorf("%s: failures %q, state %v; want none, Trusted", f.Name, got, r.State())
			}
			for _, want := range []string{verify.TimeStampValidated, verify.TimeStampTrusted, verify.SigningCredentialTrusted} {
				if !slices.Contains(codes, want) {
					t.Errorf("%s: no %s in %q", f.Name, want, codes)
				}
			}
			if got := tokenTime(t, out); !got.Equal(stampTime) {
				t.Errorf("%s: token time %v, want %v", f.Name, got, stampTime)
			}
			// Hard binding unaffected; stripping gives the input back.
			if stripped, _ := jpeg.Strip(out); string(stripped) != string(mustStrip(t, in)) {
				t.Errorf("%s: Strip(signed) differs from Strip(input)", f.Name)
			}
		}
		if lengths[0] != lengths[1] || lengths[1] != lengths[2] {
			t.Errorf("%s: signed sizes %v differ with token size", f.Name, lengths)
		}

		// Without the token the same check fails on the expired signer,
		// which shows it is the token's time that made the difference.
		r := verify.File(plain, &verify.Options{TrustAnchors: anchors(t), Now: afterExpiry})
		if got := failures(r); !slices.Equal(got, []string{verify.SigningCredentialExpired}) {
			t.Errorf("%s: no time-stamp, after expiry: failures %q, want [%s]", f.Name, got, verify.SigningCredentialExpired)
		}
	}
}

// TestTimestampFailures: every way the TSA can fail stops signing with an
// error and no output.
func TestTimestampFailures(t *testing.T) {
	chain, key := testPKI(t)
	in := readFixture(t, unsignedJPEGs(t)[0])
	tests := []struct {
		name    string
		setup   func(*testtsa.TSA)
		reserve int
		want    error
	}{
		{"HTTP 503", func(f *testtsa.TSA) { f.Status = http.StatusServiceUnavailable }, 0, ErrTimestamp},
		{"rejected", func(f *testtsa.TSA) { f.Reject = true }, 0, ErrTimestamp},
		{"wrong imprint", func(f *testtsa.TSA) { f.BadDigest = true }, 0, ErrTimestamp},
		{"wrong nonce", func(f *testtsa.TSA) { f.BadNonce = true }, 0, ErrTimestamp},
		{"no TSA certificate", func(f *testtsa.TSA) { f.NoCerts = true }, 0, ErrTimestamp},
		{"token over reserve", func(*testtsa.TSA) {}, 200, ErrTimestampTooLarge},
	}
	for _, tt := range tests {
		tsa, srv := newFakeTSA(t)
		tt.setup(tsa)
		out, err := JPEG(in, &Options{Chain: chain, Signer: key, TSAURL: srv.URL, TimestampReserve: tt.reserve})
		if !errors.Is(err, tt.want) || out != nil {
			t.Errorf("%s: err = %v, output %d bytes; want %v and no output", tt.name, err, len(out), tt.want)
		}
		if tsa.Requests() != 1 {
			t.Errorf("%s: %d TSA requests, want 1", tt.name, tsa.Requests())
		}
	}

	// Unreachable TSA.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := JPEG(in, &Options{Chain: chain, Signer: key, TSAURL: url}); !errors.Is(err, ErrTimestamp) {
		t.Errorf("unreachable TSA: err = %v, want ErrTimestamp", err)
	}
}

func TestTimestampOptions(t *testing.T) {
	chain, key := testPKI(t)
	for _, o := range []Options{
		{TSAURL: "timestamp.example"},
		{TSAURL: "ftp://timestamp.example"},
		{TSAURL: "http://"},
		{TSAURL: "http://tsa.example", TimestampReserve: -1},
		{TimestampReserve: MaxTimestampReserve + 1},
	} {
		o.Chain, o.Signer = chain, key
		if _, err := Build(&o); !errors.Is(err, ErrBadTSA) {
			t.Errorf("TSAURL %q reserve %d: err = %v, want ErrBadTSA", o.TSAURL, o.TimestampReserve, err)
		}
	}
	// No TSA: no network and an empty unprotected header, as before.
	m, err := Build(&Options{Chain: chain, Signer: key})
	if err != nil || m.tstSize != 0 {
		t.Errorf("no TSA: tstSize %d, err %v", m.tstSize, err)
	}
}

// TestC2patoolTimestamp: c2patool accepts our time-stamped JPEGs and trusts
// the time-stamp when the test root is trusted.
func TestC2patoolTimestamp(t *testing.T) {
	if _, err := exec.LookPath("c2patool"); err != nil {
		t.Skip("c2patool not on PATH")
	}
	settings := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(settings, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("C2PATOOL_SETTINGS", settings)
	chain, key := testPKI(t)
	_, srv := newFakeTSA(t)
	for _, f := range unsignedJPEGs(t) {
		out, err := JPEG(readFixture(t, f), &Options{Chain: chain, Signer: key, TSAURL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), f.Name)
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []struct {
			args      []string
			state     string
			failCodes []string
			success   []string
		}{
			{nil, "Valid", []string{verify.SigningCredentialUntrusted}, []string{verify.TimeStampValidated}},
			{[]string{"trust", "--trust_anchors", "../testdata/pki/trust-anchors.pem"}, "Trusted", nil,
				[]string{verify.TimeStampValidated, verify.TimeStampTrusted, verify.SigningCredentialTrusted}},
		} {
			b, err := exec.Command("c2patool", append([]string{path, "--detailed"}, mode.args...)...).Output()
			if err != nil {
				t.Fatalf("%s: c2patool: %v", f.Name, err)
			}
			var rep struct {
				State   string `json:"validation_state"`
				Results struct {
					Active struct {
						Success []struct{ Code string } `json:"success"`
						Failure []struct{ Code string } `json:"failure"`
					} `json:"activeManifest"`
				} `json:"validation_results"`
			}
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatalf("%s: c2patool output: %v", f.Name, err)
			}
			var fail, ok []string
			for _, x := range rep.Results.Active.Failure {
				fail = append(fail, x.Code)
			}
			for _, x := range rep.Results.Active.Success {
				ok = append(ok, x.Code)
			}
			if rep.State != mode.state || !slices.Equal(fail, mode.failCodes) {
				t.Errorf("%s %v: c2patool state %s, failures %q; want %s, %q", f.Name, mode.args, rep.State, fail, mode.state, mode.failCodes)
			}
			for _, want := range mode.success {
				if !slices.Contains(ok, want) {
					t.Errorf("%s %v: c2patool success codes %q lack %s", f.Name, mode.args, ok, want)
				}
			}
		}
	}
}

// tokenTime reads the signed file back and returns its token's genTime.
func tokenTime(t *testing.T, signed []byte) time.Time {
	t.Helper()
	st, err := jpeg.Extract(signed)
	if err != nil {
		t.Fatal(err)
	}
	root, err := jumbf.Parse(st.JUMBF)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ts := ms[len(ms)-1].Signature.Timestamps
	if len(ts) != 1 || ts[0].Version != 2 {
		t.Fatalf("want one sigTst2 token, got %d", len(ts))
	}
	tok, err := timestamp.Parse(ts[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Time
}

func statusCodes(r *verify.Result) []string {
	var out []string
	for _, s := range r.Statuses() {
		out = append(out, s.Code)
	}
	return out
}

func readFixture(t *testing.T, f fixtures.Fixture) []byte {
	t.Helper()
	b, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustStrip(t *testing.T, b []byte) []byte {
	t.Helper()
	s, err := jpeg.Strip(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
