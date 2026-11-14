package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/keys/awskms/awskmstest"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
)

// TestSignThroughKMS is the phase's check for this provider: files signed
// through an awskms: URI verify in C2paSeal and in c2patool.
func TestSignThroughKMS(t *testing.T) {
	awskmstest.Isolate(t)
	f := awskmstest.NewServer(t)
	signer, err := sign.OpenKey(t.Context(), f.URI())
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(*ecdsa.PublicKey).Equal(f.Key.Public()) || signer.(*Signer).KeyID() != awskmstest.ARN {
		t.Fatal("signer does not hold the KMS key")
	}
	signtest.Check(t, signer, signtest.Chain(t, signer.Public()))
	if f.Calls("GetPublicKey") != 1 || f.Calls("Sign") != 2 {
		t.Errorf("KMS calls: %d GetPublicKey, %d Sign; want 1 and 2", f.Calls("GetPublicKey"), f.Calls("Sign"))
	}
	// Every request was SigV4-signed for KMS in the ARN's region.
	for _, a := range f.Authorizations() {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !strings.Contains(a, "/eu-west-1/kms/aws4_request") {
			t.Errorf("Authorization %q", a)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	awskmstest.Isolate(t)
	ctx := t.Context()
	f := awskmstest.NewServer(t)
	ep := "?endpoint=" + f.URL
	for _, tc := range []struct {
		name, uri, want string
		setup           func()
	}{
		{"alias without region", "awskms:" + awskmstest.Alias + ep, "no region", nil},
		{"alias with region", "awskms:" + awskmstest.Alias + "?region=us-east-2&endpoint=" + f.URL, "", nil},
		{"host form", "awskms://" + awskmstest.Alias + "?region=us-east-2&endpoint=" + f.URL, "", nil},
		{"no key", "awskms:", "URI names no key", nil},
		{"unknown key", "awskms:arn:aws:kms:eu-west-1:111122223333:key/nope" + ep, "NotFoundException", nil},
		{"wrong spec", f.URI(), "needs ECC_NIST_P256", func() { f.Spec = "ECC_NIST_P384" }},
		{"wrong usage", f.URI(), "want SIGN_VERIFY", func() { f.Spec, f.Usage = "", "ENCRYPT_DECRYPT" }},
		{"missing profile", "awskms:" + awskmstest.ARN + "?profile=nope&endpoint=" + f.URL, "load AWS config", func() { f.Usage = "" }},
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
	f.Key = rsaKey
	if _, err := sign.OpenKey(ctx, f.URI()); err == nil || !strings.Contains(err.Error(), "want ECDSA P-256") {
		t.Errorf("RSA public key: %v", err)
	}
}

func TestSignErrors(t *testing.T) {
	awskmstest.Isolate(t)
	f := awskmstest.NewServer(t)
	signer, err := sign.OpenKey(t.Context(), f.URI())
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
	f.WrongSignature = true
	if _, err := signer.Sign(nil, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("wrong signature from KMS: %v", err)
	}
	f.WrongSignature = false
	sig, err := signer.Sign(nil, digest[:], nil)
	if err != nil || !ecdsa.VerifyASN1(f.Key.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Errorf("Sign = %x, %v", sig, err)
	}
	f.Close()
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
