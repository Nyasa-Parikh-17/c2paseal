package c2paseal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

func TestTrustLoaders(t *testing.T) {
	dir, _ := fixtures.Dir()
	if a, err := LoadTrustList(filepath.Join(dir, "pki", "trust-anchors.pem")); err != nil || len(a) != 1 {
		t.Errorf("LoadTrustList: %v, %d", err, len(a))
	}
	if l, err := LoadAllowedList(filepath.Join(dir, "pki", "leaf.pem")); err != nil || len(l) != 1 {
		t.Errorf("LoadAllowedList: %v, %d", err, len(l))
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllowedList(empty); err == nil {
		t.Error("LoadAllowedList accepted a file without entries")
	}
	if _, err := LoadAllowedList("missing.pem"); err == nil {
		t.Error("LoadAllowedList: missing file")
	}
	if ekus, err := LoadTrustConfig(empty); err != nil || len(ekus) != 0 {
		t.Errorf("LoadTrustConfig: %v %v", err, ekus)
	}
	if _, err := LoadTrustConfig("missing.cfg"); err == nil {
		t.Error("LoadTrustConfig: missing file")
	}
	for s, ok := range map[string]bool{"1.2.840": true, "2.5.29.37": true, "3.1": false, "1": false, "1.a": false, "1..2": false, "1.02": false, "-1.2": false} {
		if _, got := parseOID(s); got != ok {
			t.Errorf("parseOID(%q) = %v", s, got)
		}
	}
}

// TestOfficialTrustLists: both official C2PA trust lists load.
func TestOfficialTrustLists(t *testing.T) {
	dir, _ := fixtures.Dir()
	for name, min := range map[string]int{"C2PA-TRUST-LIST.pem": 20, "C2PA-TSA-TRUST-LIST.pem": 10} {
		a, err := LoadTrustList(filepath.Join(dir, "trust", name))
		if err != nil || len(a) < min {
			t.Errorf("%s: %v, %d certificates", name, err, len(a))
		}
	}
}
