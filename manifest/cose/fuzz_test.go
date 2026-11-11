package cose

import (
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// signaturePayloads returns the COSE_Sign1 bytes of every signed fixture.
func signaturePayloads() [][]byte {
	var out [][]byte
	var walk func(b *jumbf.Box)
	walk = func(b *jumbf.Box) {
		if b.Label() == "c2pa.signature" {
			for _, c := range b.Contents() {
				if c.Type == "cbor" {
					out = append(out, c.Payload)
				}
			}
		}
		for _, c := range b.Contents() {
			if c.IsSuperbox() {
				walk(c)
			}
		}
	}
	for _, b := range fixtures.SignedFiles() {
		if _, root, err := asset.Extract(b); err == nil {
			walk(root)
		}
	}
	return out
}

// FuzzDecode checks the COSE_Sign1 decoder never panics, keeps the original
// bytes and returns only well-formed time-stamp entries.
func FuzzDecode(f *testing.F) {
	for _, p := range signaturePayloads() {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Decode(b)
		if err != nil {
			return
		}
		if string(s.Raw) != string(b) {
			t.Fatal("decoded message does not keep its original bytes")
		}
		for _, ts := range s.Timestamps {
			if ts.Version != 1 && ts.Version != 2 {
				t.Fatalf("time-stamp version %d", ts.Version)
			}
		}
		_ = AlgName(s.Alg)
	})
}
