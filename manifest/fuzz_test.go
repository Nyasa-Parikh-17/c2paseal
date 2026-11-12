package manifest

import (
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// fixtureStores returns the manifest store superboxes of the signed fixtures.
func fixtureStores() []*jumbf.Box {
	var out []*jumbf.Box
	for _, b := range fixtures.SignedFiles() {
		if _, root, err := asset.Extract(b); err == nil {
			out = append(out, root)
		}
	}
	return out
}

// FuzzDecodeClaim checks the claim decoder never panics and keeps the
// original bytes (byte-exactness on the read path).
func FuzzDecodeClaim(f *testing.F) {
	for _, root := range fixtureStores() {
		if ms, err := DecodeStore(root); err == nil {
			for _, m := range ms {
				f.Add(m.Claim.Raw)
			}
		}
	}
	f.Add([]byte{0xA0})
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeClaim(b)
		if err != nil {
			return
		}
		if string(c.Raw) != string(b) {
			t.Fatal("decoded claim does not keep its original bytes")
		}
	})
}

// FuzzDecodeStore parses a JUMBF store and decodes every manifest, then
// resolves and hashes every assertion reference, as Verify does.
func FuzzDecodeStore(f *testing.F) {
	for _, root := range fixtureStores() {
		f.Add(root.Bytes())
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		root, err := jumbf.Parse(b)
		if err != nil {
			return
		}
		ms, err := DecodeStore(root)
		if err != nil {
			return
		}
		for _, m := range ms {
			if m.Claim == nil {
				continue
			}
			refs := append(append([]HashedURI{}, m.Claim.CreatedAssertions...), m.Claim.GatheredAssertions...)
			for _, ref := range refs {
				if box, err := Resolve(root, m.Box, ref.URL); err == nil {
					_, _ = HashBox(m.Claim.Alg, box)
				}
			}
		}
	})
}

// FuzzDecodeClaimV1 decodes arbitrary bytes as a C2PA 1.x claim.
func FuzzDecodeClaimV1(f *testing.F) {
	for _, root := range fixtureStores() {
		if ms, err := DecodeStore(root); err == nil {
			for _, m := range ms {
				if m.Claim.Version == 1 {
					f.Add(m.Claim.Raw)
				}
			}
		}
	}
	f.Add([]byte{0xA0})
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeClaimV1(b)
		if err != nil {
			return
		}
		if string(c.Raw) != string(b) || c.Version != 1 || c.ClaimGeneratorInfo == nil {
			t.Fatalf("decoded v1 claim %+v", c)
		}
		_ = c.Assertions()
	})
}
