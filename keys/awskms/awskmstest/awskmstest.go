// Package awskmstest is a fake AWS KMS endpoint for tests: it answers
// GetPublicKey and Sign the way AWS KMS does (JSON 1.1 protocol,
// X-Amz-Target "TrentService.<Operation>") with a local P-256 key, so code
// that signs through awskms: URIs can be tested without AWS.
package awskmstest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ARN and Alias name the fake's one key. The ARN's region is eu-west-1.
const (
	ARN   = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	Alias = "alias/c2pa"
)

// Server is a running fake. Set the knobs before the requests they affect.
type Server struct {
	*httptest.Server
	// Key is the private key behind ARN. NewServer makes a P-256 key;
	// tests may replace it (for example with an RSA key).
	Key crypto.Signer
	// Spec and Usage are the KeySpec and KeyUsage reported; empty means
	// ECC_NIST_P256 and SIGN_VERIFY.
	Spec, Usage string
	// WrongSignature makes Sign answer with a signature from another key.
	WrongSignature bool

	mu    sync.Mutex
	calls map[string]int
	auth  []string
}

// NewServer starts a fake, closed when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Key: key, calls: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// URI returns the awskms: URI of the fake's key at this endpoint.
func (s *Server) URI() string { return "awskms:" + ARN + "?endpoint=" + s.URL }

// Calls returns how many times the operation ("GetPublicKey", "Sign") was
// called.
func (s *Server) Calls(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[op]
}

// Authorizations returns the Authorization headers received, in order.
func (s *Server) Authorizations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	s.mu.Lock()
	s.calls[op]++
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	key, spec, usage, wrong := s.Key, s.Spec, s.Usage, s.WrongSignature
	s.mu.Unlock()
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
	if in.KeyID != ARN && in.KeyID != Alias {
		fail(w, "NotFoundException", "Key '"+in.KeyID+"' does not exist")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch op {
	case "GetPublicKey":
		der, _ := x509.MarshalPKIXPublicKey(key.Public())
		if spec == "" {
			spec = "ECC_NIST_P256"
		}
		if usage == "" {
			usage = "SIGN_VERIFY"
		}
		json.NewEncoder(w).Encode(map[string]any{
			"KeyId": ARN, "KeySpec": spec, "KeyUsage": usage, "PublicKey": der,
			"SigningAlgorithms": []string{"ECDSA_SHA_256"},
		})
	case "Sign":
		if in.MessageType != "DIGEST" || in.SigningAlgorithm != "ECDSA_SHA_256" || len(in.Message) != 32 {
			fail(w, "ValidationException", "unexpected sign request")
			return
		}
		k := key
		if wrong {
			k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		sig, err := k.Sign(rand.Reader, in.Message, crypto.SHA256)
		if err != nil {
			fail(w, "KMSInternalException", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"KeyId": ARN, "Signature": sig, "SigningAlgorithm": "ECDSA_SHA_256"})
	default:
		fail(w, "UnknownOperationException", op)
	}
}

func fail(w http.ResponseWriter, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

// Isolate keeps the AWS SDK away from the machine's credentials and config
// for the rest of the test: static test credentials (access key AKIDTEST),
// no region, no shared files, no instance metadata.
func Isolate(t *testing.T) {
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
