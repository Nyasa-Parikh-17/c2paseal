package signtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestCheck runs the provider check with an in-memory key: the baseline
// that every key provider's test repeats through its own signer.
func TestCheck(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain(t, key.Public())
	if len(chain) != 2 || !chain[0].PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) || chain[0].CheckSignatureFrom(chain[1]) != nil {
		t.Fatal("Chain did not issue a certificate for the key under the intermediate")
	}
	if files := Check(t, key, chain); len(files) != 2 {
		t.Errorf("Check signed %d files", len(files))
	}
}
