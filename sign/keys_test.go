package sign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

func TestOpenKeyFile(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(filepath.Join(dir, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParsePrivateKey(mustRead(t, abs))
	if err != nil {
		t.Fatal(err)
	}
	// A relative path from this package's directory, as file:<path> and
	// as a plain path.
	rel, err := filepath.Rel(mustGetwd(t), abs)
	if err != nil {
		t.Fatal(err)
	}
	slashAbs := filepath.ToSlash(abs)
	if !strings.HasPrefix(slashAbs, "/") {
		slashAbs = "/" + slashAbs // file:///C:/...
	}
	for _, uri := range []string{
		abs,
		rel,
		"file:" + filepath.ToSlash(rel),
		"file://" + slashAbs,
		"FILE://localhost" + slashAbs,
		"file://" + strings.ReplaceAll(slashAbs, "pki", "%70ki"), // escaped
	} {
		t.Run(uri, func(t *testing.T) {
			s, err := OpenKey(context.Background(), uri)
			if err != nil {
				t.Fatal(err)
			}
			if !s.Public().(*ecdsa.PublicKey).Equal(want.Public()) {
				t.Error("opened a different key")
			}
		})
	}
	if runtime.GOOS == "windows" && !isDrive(abs) {
		t.Errorf("isDrive(%q) = false", abs)
	}
}

func TestOpenKeyErrors(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ uri, want string }{
		{"missing.pem", "sign: key: "},
		{"file://host.example/k.pem", "with a host are not supported"},
		{"file:", "without a path"},
		{"awskms:arn:aws:kms:eu-west-1:111122223333:key/abc", "import github.com/Nyasa-Parikh-17/c2paseal/keys/awskms"},
		{"gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "import github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms"},
		{"vault://secret/k?token=s3cret", `no key provider for scheme "vault" (have file`},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			_, err := OpenKey(ctx, tc.uri)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("error leaks the query: %v", err)
			}
		})
	}
	// A file that is not a key names the file.
	f := filepath.Join(t.TempDir(), "notakey.pem")
	os.WriteFile(f, []byte("hello"), 0o600)
	if _, err := OpenKey(ctx, f); err == nil || !strings.Contains(err.Error(), "no PEM block") || !strings.Contains(err.Error(), f) {
		t.Errorf("not a key: %v", err)
	}
}

type testProvider struct {
	key  crypto.Signer
	seen *url.URL
}

func (p *testProvider) Open(_ context.Context, u *url.URL) (crypto.Signer, error) {
	p.seen = u
	if u.Query().Get("fail") != "" {
		return nil, errors.New("refused")
	}
	return p.key, nil
}

func TestRegisterKeyProvider(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &testProvider{key: key}
	RegisterKeyProvider("TestKMS", p) // schemes are case-insensitive
	t.Cleanup(func() {
		providersMu.Lock()
		delete(providers, "testkms")
		providersMu.Unlock()
	})
	s, err := OpenKey(context.Background(), "testkms:keys/one?region=x")
	if err != nil || s != crypto.Signer(key) || p.seen.Opaque != "keys/one" || p.seen.Query().Get("region") != "x" {
		t.Fatalf("OpenKey = %v, %v; provider saw %v", s, err, p.seen)
	}
	if _, err := OpenKey(context.Background(), "testkms:k?fail=1"); err == nil || !strings.Contains(err.Error(), "sign: key testkms:k: refused") {
		t.Errorf("provider error: %v", err)
	}
	if got := KeySchemes(); !strings.Contains(strings.Join(got, ","), "file,testkms") {
		t.Errorf("KeySchemes = %v", got)
	}
	for name, f := range map[string]func(){
		"duplicate": func() { RegisterKeyProvider("testkms", p) },
		"file":      func() { RegisterKeyProvider("file", p) },
		"nil":       func() { RegisterKeyProvider("other", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func TestParsePrivateKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "no PEM block"},
		{"garbage DER", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "sign: key: "},
		{"garbage SEC 1", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", "sign: key: "},
	} {
		if _, err := ParsePrivateKey([]byte(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
