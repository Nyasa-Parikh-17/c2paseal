package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scopes an API key can have.
const (
	scopeSign   = "sign"
	scopeVerify = "verify"
)

// apiKey is one line of the API key file. Only the SHA-256 of the key is
// stored, so the file holds no secrets.
type apiKey struct {
	name   string
	hash   [sha256.Size]byte
	scopes []string
	perMin float64 // requests per minute
	bucket *bucket
}

// keyring holds the API keys.
type keyring struct {
	keys []*apiKey
}

// parseKeyring reads an API key file. Each non-empty line that is not a
// comment is
//
//	<name> <sha256 hex of the key> [rate=<n>/min] [scopes=sign,verify]
//
// defaultRate applies when a line has no rate. Names must be unique.
func parseKeyring(r io.Reader, defaultRate float64) (*keyring, error) {
	kr := &keyring{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return nil, fmt.Errorf("api keys line %d: want <name> <sha256 hex> [rate=N/min] [scopes=…]", n)
		}
		k := &apiKey{name: f[0], scopes: []string{scopeSign, scopeVerify}, perMin: defaultRate}
		if seen[k.name] {
			return nil, fmt.Errorf("api keys line %d: duplicate name %q", n, k.name)
		}
		seen[k.name] = true
		h, err := hex.DecodeString(f[1])
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("api keys line %d: %q is not a SHA-256 hex digest (use `sealsvc hash-key`)", n, f[1])
		}
		copy(k.hash[:], h)
		for _, opt := range f[2:] {
			name, val, _ := strings.Cut(opt, "=")
			switch name {
			case "rate":
				r, err := parseRate(val)
				if err != nil {
					return nil, fmt.Errorf("api keys line %d: %w", n, err)
				}
				k.perMin = r
			case "scopes":
				k.scopes = nil
				for _, s := range strings.Split(val, ",") {
					if s != scopeSign && s != scopeVerify {
						return nil, fmt.Errorf("api keys line %d: unknown scope %q", n, s)
					}
					k.scopes = append(k.scopes, s)
				}
			default:
				return nil, fmt.Errorf("api keys line %d: unknown option %q", n, opt)
			}
		}
		k.bucket = newBucket(k.perMin)
		kr.keys = append(kr.keys, k)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(kr.keys) == 0 {
		return nil, fmt.Errorf("api keys: no keys")
	}
	return kr, nil
}

// parseRate parses "<n>/min" or "<n>/s".
func parseRate(s string) (float64, error) {
	num, unit, ok := strings.Cut(s, "/")
	n, err := strconv.ParseFloat(num, 64)
	if !ok || err != nil || n <= 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, fmt.Errorf("rate %q: want <n>/min or <n>/s", s)
	}
	switch unit {
	case "min":
		return n, nil
	case "s":
		return n * 60, nil
	}
	return 0, fmt.Errorf("rate %q: want <n>/min or <n>/s", s)
}

// lookup returns the key whose hash matches the bearer token in r, or nil.
// Every stored hash is compared, in constant time, so the time taken does
// not depend on which key (if any) matched.
func (kr *keyring) lookup(r *http.Request) *apiKey {
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || token == "" {
		return nil
	}
	h := sha256.Sum256([]byte(token))
	var found *apiKey
	for _, k := range kr.keys {
		if subtle.ConstantTimeCompare(h[:], k.hash[:]) == 1 {
			found = k
		}
	}
	return found
}

func (k *apiKey) can(scope string) bool { return slices.Contains(k.scopes, scope) }

// newAPIKey returns a fresh random API key and the SHA-256 hex to put in
// the key file.
func newAPIKey() (key, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	key = "sk_" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(key))
	return key, hex.EncodeToString(h[:]), nil
}

// bucket is a token bucket: perMin tokens a minute, holding at most
// max(perMin, 1), so a key can burst up to its per-minute rate.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(perMin float64) *bucket {
	burst := math.Max(perMin, 1)
	return &bucket{rate: perMin / 60, burst: burst, tokens: burst}
}

// take takes a token at now. If none is left it returns how long until one
// is.
func (b *bucket) take(now time.Time) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}
