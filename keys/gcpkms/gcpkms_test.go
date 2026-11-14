package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testName = "projects/c2paseal-test/locations/europe-west1/keyRings/ring/cryptoKeys/signer/cryptoKeyVersions/1"

// fakeKMS answers GetPublicKey and AsymmetricSign the way Cloud KMS's REST
// API does, with a local key. The knobs break one thing each.
type fakeKMS struct {
	key       crypto.Signer
	algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm // default EC_SIGN_P256_SHA256
	badPemCRC bool
	badSigCRC bool
	noVerify  bool // verifiedDigestCrc32c false
	wrongName bool
	wrongSig  bool

	mu    sync.Mutex
	calls map[string]int
	auth  []string
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	var op, name string
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/publicKey"):
		op, name = "GetPublicKey", strings.TrimSuffix(path, "/publicKey")
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":asymmetricSign"):
		op, name = "AsymmetricSign", strings.TrimSuffix(path, ":asymmetricSign")
	default:
		gerr(w, http.StatusNotFound, "NOT_FOUND", "no route "+r.Method+" "+r.URL.Path)
		return
	}
	f.mu.Lock()
	f.calls[op]++
	f.mu.Unlock()
	if name != testName {
		gerr(w, http.StatusNotFound, "NOT_FOUND", "CryptoKeyVersion "+name+" not found.")
		return
	}
	respName := name
	if f.wrongName {
		respName = strings.TrimSuffix(name, "1") + "2"
	}
	var out []byte
	switch op {
	case "GetPublicKey":
		der, _ := x509.MarshalPKIXPublicKey(f.key.Public())
		p := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		alg := f.algorithm
		if alg == 0 {
			alg = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
		}
		c := crc32c([]byte(p))
		if f.badPemCRC {
			c++
		}
		out, _ = protojson.MarshalOptions{UseEnumNumbers: true}.Marshal(&kmspb.PublicKey{
			Pem: p, Algorithm: alg, PemCrc32C: wrapperspb.Int64(c), Name: respName,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		})
	case "AsymmetricSign":
		body, _ := io.ReadAll(r.Body)
		var req kmspb.AsymmetricSignRequest
		if err := protojson.Unmarshal(body, &req); err != nil {
			gerr(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		d := req.GetDigest().GetSha256()
		if len(d) != 32 || req.GetDigestCrc32C().GetValue() != crc32c(d) {
			gerr(w, http.StatusBadRequest, "INVALID_ARGUMENT", "bad digest or checksum")
			return
		}
		k := f.key
		if f.wrongSig {
			k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		sig, err := k.Sign(rand.Reader, d, crypto.SHA256)
		if err != nil {
			gerr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		c := crc32c(sig)
		if f.badSigCRC {
			c++
		}
		out, _ = protojson.MarshalOptions{UseEnumNumbers: true}.Marshal(&kmspb.AsymmetricSignResponse{
			Signature: sig, SignatureCrc32C: wrapperspb.Int64(c), VerifiedDigestCrc32C: !f.noVerify,
			Name: respName, ProtectionLevel: kmspb.ProtectionLevel_HSM,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func gerr(w http.ResponseWriter, code int, status, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg, "status": status}})
}

func newFake(t *testing.T) (*fakeKMS, *httptest.Server) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKMS{key: key}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func open(t *testing.T, srv *httptest.Server) *Signer {
	t.Helper()
	s, err := sign.OpenKey(t.Context(), "gcpkms:"+testName+"?endpoint="+srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.(*Signer).Close() })
	return s.(*Signer)
}

// TestSignThroughKMS is the phase's check for this provider: files signed
// through a gcpkms: URI verify in C2paSeal and in c2patool.
func TestSignThroughKMS(t *testing.T) {
	f, srv := newFake(t)
	signer := open(t, srv)
	if !signer.Public().(*ecdsa.PublicKey).Equal(f.key.Public()) || signer.Name() != testName {
		t.Fatal("signer does not hold the KMS key")
	}
	signtest.Check(t, signer, signtest.Chain(t, signer.Public()))
	if f.calls["GetPublicKey"] != 1 || f.calls["AsymmetricSign"] != 2 {
		t.Errorf("KMS calls: %v; want 1 GetPublicKey and 2 AsymmetricSign", f.calls)
	}
	// A plaintext endpoint never gets credentials.
	for _, a := range f.auth {
		if a != "" {
			t.Errorf("Authorization header sent to an http:// endpoint: %q", a)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	ctx := t.Context()
	f, srv := newFake(t)
	ep := "?endpoint=" + srv.URL
	for _, tc := range []struct {
		name, uri, want string
		setup           func()
	}{
		{"host form", "gcpkms://" + testName + ep, "", nil},
		{"no key", "gcpkms:", "names no key version", nil},
		{"not a version name", "gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k" + ep, "is not a key version name", nil},
		{"unknown key", "gcpkms:" + strings.Replace(testName, "signer", "other", 1) + ep, "not found", nil},
		{"bad endpoint", "gcpkms:" + testName + "?endpoint=ftp://x", "is not an http(s) URL", nil},
		{"wrong algorithm", "gcpkms:" + testName + ep, "needs EC_SIGN_P256_SHA256", func() { f.algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384 }},
		{"pem checksum", "gcpkms:" + testName + ep, "CRC32C mismatch", func() { f.algorithm, f.badPemCRC = 0, true }},
		{"wrong name", "gcpkms:" + testName + ep, "public key response is for", func() { f.badPemCRC, f.wrongName = false, true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			s, err := sign.OpenKey(ctx, tc.uri)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				s.(*Signer).Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSignErrors(t *testing.T) {
	f, srv := newFake(t)
	signer := open(t, srv)
	digest := sha256.Sum256([]byte("x"))
	if _, err := signer.Sign(nil, digest[:20], nil); err == nil {
		t.Error("short digest signed")
	}
	if _, err := signer.Sign(nil, digest[:], crypto.SHA512); err == nil {
		t.Error("SHA-512 accepted")
	}
	for _, tc := range []struct {
		name string
		knob *bool
		want string
	}{
		{"digest not verified", &f.noVerify, "KMS did not verify its CRC32C"},
		{"signature checksum", &f.badSigCRC, "signature corrupted in transit"},
		{"wrong name", &f.wrongName, "signature response is for"},
		{"wrong key", &f.wrongSig, "does not verify with the key's public key"},
	} {
		*tc.knob = true
		if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		*tc.knob = false
	}
	sig, err := signer.Sign(nil, digest[:], nil)
	if err != nil || !ecdsa.VerifyASN1(f.key.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Errorf("Sign = %x, %v", sig, err)
	}
	srv.Close()
	if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "gcpkms: sign:") {
		t.Errorf("KMS down: %v", err)
	}
}

// TestRealKMS signs with a real Cloud KMS key version when
// C2PASEAL_GCPKMS_KEY holds its URI (gcpkms:projects/…) and Application
// Default Credentials are available. The certificate is issued on the fly
// under the TEST ONLY intermediate, so only the key is needed. CI runs it
// only when the repository has those secrets.
func TestRealKMS(t *testing.T) {
	uri := os.Getenv("C2PASEAL_GCPKMS_KEY")
	if uri == "" {
		t.Skip("set C2PASEAL_GCPKMS_KEY (and Application Default Credentials) to sign with a real Cloud KMS key")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60e9)
	defer cancel()
	signer, err := sign.OpenKey(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.(*Signer).Close()
	signtest.Check(t, signer, signtest.Chain(t, signer.Public()))
}
