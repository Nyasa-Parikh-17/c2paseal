package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
)

const testARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// fakeKMS answers GetPublicKey and Sign the way AWS KMS does (JSON 1.1
// protocol, X-Amz-Target "TrentService.<Operation>"), with a local key.
type fakeKMS struct {
	key      crypto.Signer
	spec     string // KeySpec reported; default ECC_NIST_P256
	usage    string // KeyUsage reported; default SIGN_VERIFY
	wrongSig bool   // sign with another key

	mu    sync.Mutex
	calls map[string]int
	auth  []string // Authorization headers seen
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[op]++
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	var in struct {
		KeyID            string `json:"KeyId"`
		Message          []byte
		MessageType      string
		SigningAlgorithm string
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, "SerializationException", err.Error())
		return
	}
	if in.KeyID != testARN && in.KeyID != "alias/c2pa" {
		fail(w, "NotFoundException", "Key '"+in.KeyID+"' does not exist")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch op {
	case "GetPublicKey":
		der, _ := x509.MarshalPKIXPublicKey(f.key.Public())
		spec, usage := f.spec, f.usage
		if spec == "" {
			spec = "ECC_NIST_P256"
		}
		if usage == "" {
			usage = "SIGN_VERIFY"
		}
		json.NewEncoder(w).Encode(map[string]any{
			"KeyId": testARN, "KeySpec": spec, "KeyUsage": usage, "PublicKey": der,
			"SigningAlgorithms": []string{"ECDSA_SHA_256"},
		})
	case "Sign":
		if in.MessageType != "DIGEST" || in.SigningAlgorithm != "ECDSA_SHA_256" || len(in.Message) != 32 {
			fail(w, "ValidationException", "unexpected sign request")
			return
		}
		k := f.key
		if f.wrongSig {
			k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		sig, err := k.Sign(rand.Reader, in.Message, crypto.SHA256)
		if err != nil {
			fail(w, "KMSInternalException", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"KeyId": testARN, "Signature": sig, "SigningAlgorithm": "ECDSA_SHA_256"})
	default:
		fail(w, "UnknownOperationException", op)
	}
}

func fail(w http.ResponseWriter, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

// isolate keeps the AWS SDK away from this machine's credentials and
// config: static test credentials, no shared files, no instance metadata.
func isolate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
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

// TestSignThroughKMS is the phase's check for this provider: files signed
// through an awskms: URI verify in C2paSeal and in c2patool.
func TestSignThroughKMS(t *testing.T) {
	isolate(t)
	f, srv := newFake(t)
	signer, err := sign.OpenKey(t.Context(), "awskms:"+testARN+"?endpoint="+srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(*ecdsa.PublicKey).Equal(f.key.Public()) || signer.(*Signer).KeyID() != testARN {
		t.Fatal("signer does not hold the KMS key")
	}
	signtest.Check(t, signer, signtest.Chain(t, signer.Public()))
	if f.calls["GetPublicKey"] != 1 || f.calls["Sign"] != 2 {
		t.Errorf("KMS calls: %v; want 1 GetPublicKey and 2 Sign", f.calls)
	}
	// Every request was SigV4-signed for KMS in the ARN's region.
	for _, a := range f.auth {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !strings.Contains(a, "/eu-west-1/kms/aws4_request") {
			t.Errorf("Authorization %q", a)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	isolate(t)
	ctx := t.Context()
	f, srv := newFake(t)
	for _, tc := range []struct {
		name, uri, want string
		setup           func()
	}{
		{"alias without region", "awskms:alias/c2pa?endpoint=" + srv.URL, "no region", nil},
		{"alias with region", "awskms:alias/c2pa?region=us-east-2&endpoint=" + srv.URL, "", nil},
		{"host form", "awskms://alias/c2pa?region=us-east-2&endpoint=" + srv.URL, "", nil},
		{"no key", "awskms:", "URI names no key", nil},
		{"unknown key", "awskms:arn:aws:kms:eu-west-1:111122223333:key/nope?endpoint=" + srv.URL, "NotFoundException", nil},
		{"wrong spec", "awskms:" + testARN + "?endpoint=" + srv.URL, "needs ECC_NIST_P256", func() { f.spec = "ECC_NIST_P384" }},
		{"wrong usage", "awskms:" + testARN + "?endpoint=" + srv.URL, "want SIGN_VERIFY", func() { f.spec, f.usage = "", "ENCRYPT_DECRYPT" }},
		{"missing profile", "awskms:" + testARN + "?profile=nope&endpoint=" + srv.URL, "load AWS config", func() { f.usage = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			_, err := sign.OpenKey(ctx, tc.uri)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// A public key that is not P-256, even if KMS says ECC_NIST_P256.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.key = rsaKey
	if _, err := sign.OpenKey(ctx, "awskms:"+testARN+"?endpoint="+srv.URL); err == nil || !strings.Contains(err.Error(), "want ECDSA P-256") {
		t.Errorf("RSA public key: %v", err)
	}
}

func TestSignErrors(t *testing.T) {
	isolate(t)
	f, srv := newFake(t)
	signer, err := sign.OpenKey(t.Context(), "awskms:"+testARN+"?endpoint="+srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := signer.Sign(nil, digest[:20], crypto.SHA256); err == nil {
		t.Error("short digest signed")
	}
	if _, err := signer.Sign(nil, digest[:], crypto.SHA384); err == nil {
		t.Error("SHA-384 accepted")
	}
	f.wrongSig = true
	if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("wrong signature from KMS: %v", err)
	}
	f.wrongSig = false
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(f.key.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Errorf("Sign = %x, %v", sig, err)
	}
	srv.Close()
	if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "awskms: sign:") {
		t.Errorf("KMS down: %v", err)
	}
}

// TestRealKMS signs with a real AWS KMS key when C2PASEAL_AWSKMS_KEY holds
// its URI (for example awskms:arn:aws:kms:…) and AWS credentials are in the
// environment. The certificate is issued on the fly under the TEST ONLY
// intermediate, so only the key is needed. CI runs it only when the
// repository has those secrets.
func TestRealKMS(t *testing.T) {
	uri := os.Getenv("C2PASEAL_AWSKMS_KEY")
	if uri == "" {
		t.Skip("set C2PASEAL_AWSKMS_KEY (and AWS credentials) to sign with a real AWS KMS key")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60e9)
	defer cancel()
	signer, err := sign.OpenKey(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	signtest.Check(t, signer, signtest.Chain(t, signer.Public()))
}
