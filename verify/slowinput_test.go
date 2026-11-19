package verify

// Slow-input checks. Go's fuzzer stalls on these targets (it spends its time
// minimizing large interesting inputs, not running them), so this checks
// the property directly: random mutations of real time-stamp tokens and
// signed images, each of which must be handled quickly. A crafted file must
// not be able to tie up a verifier.

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// maxInputTime is far above the worst seen (about 15 ms), so slow CI
// machines do not fail it; an input this slow would be a denial of service.
const maxInputTime = 2 * time.Second

func TestMutatedTokensAreFast(t *testing.T) {
	var seeds [][]byte
	all, _ := fixtures.List()
	for _, fx := range all {
		b, _ := os.ReadFile(fx.Path)
		_, root, err := asset.Extract(b)
		if err != nil {
			continue
		}
		ms, err := manifest.DecodeStore(root)
		if err != nil {
			continue
		}
		for _, m := range ms {
			if m.Signature != nil {
				for _, ts := range m.Signature.Timestamps {
					seeds = append(seeds, ts.Token)
				}
			}
		}
	}
	r := rand.New(rand.NewSource(1))
	var worst time.Duration
	var total time.Duration
	n := 20000
	for i := 0; i < n; i++ {
		b := append([]byte(nil), seeds[r.Intn(len(seeds))]...)
		for k := 0; k < 1+r.Intn(8); k++ {
			switch r.Intn(4) {
			case 0:
				b[r.Intn(len(b))] ^= byte(1 << r.Intn(8))
			case 1:
				b = b[:r.Intn(len(b))+1]
			case 2:
				p := r.Intn(len(b))
				b = append(b[:p], append([]byte{byte(r.Intn(256))}, b[p:]...)...)
			case 3:
				b[r.Intn(len(b))] = byte(r.Intn(256))
			}
		}
		start := time.Now()
		fuzzToken(t, b)
		d := time.Since(start)
		total += d
		if d > worst {
			worst = d
		}
		if d > maxInputTime {
			t.Errorf("mutated token %d took %v: % x", i, d, b)
		}
	}
	t.Logf("%d seeds, %d mutated tokens: average %v, worst %v", len(seeds), n, total/time.Duration(n), worst)
}

func TestMutatedFilesAreFast(t *testing.T) {
	var seeds [][]byte
	all, _ := fixtures.List()
	for _, fx := range all {
		b, err := os.ReadFile(fx.Path)
		if err == nil && len(b) < 400<<10 {
			seeds = append(seeds, b)
		}
	}
	r := rand.New(rand.NewSource(2))
	var worst, total time.Duration
	worstName := 0
	n := 5000
	for i := 0; i < n; i++ {
		si := r.Intn(len(seeds))
		b := append([]byte(nil), seeds[si]...)
		for k := 0; k < 1+r.Intn(8); k++ {
			switch r.Intn(4) {
			case 0:
				b[r.Intn(len(b))] ^= byte(1 << r.Intn(8))
			case 1:
				b = b[:r.Intn(len(b))+1]
			case 2:
				p := r.Intn(len(b))
				b = append(b[:p], append([]byte{byte(r.Intn(256))}, b[p:]...)...)
			case 3:
				b[r.Intn(len(b))] = byte(r.Intn(256))
			}
		}
		start := time.Now()
		File(b, nil)
		d := time.Since(start)
		total += d
		if d > worst {
			worst, worstName = d, si
		}
		if d > maxInputTime {
			t.Errorf("mutated file %d (from seed %d) took %v", i, si, d)
		}
	}
	t.Logf("%d seed files, %d mutated files: average %v, worst %v (seed %d of %d bytes)", len(seeds), n, total/time.Duration(n), worst, worstName, len(seeds[worstName]))
}
