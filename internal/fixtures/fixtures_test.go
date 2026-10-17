package fixtures

import "testing"

func TestCorpusSize(t *testing.T) {
	min := map[Kind]int{Signed: 6, Broken: 5, Unsigned: 2}
	for k, n := range min {
		fs, err := ListKind(k)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) < n {
			t.Errorf("%s: %d fixtures, want at least %d", k, len(fs), n)
		}
	}
}

func TestLoadAll(t *testing.T) {
	all, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		t.Run(f.String(), func(t *testing.T) {
			exp, err := f.Expected()
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := f.Trusted()
			if err != nil {
				t.Fatal(err)
			}
			switch f.Kind {
			case Signed:
				for _, e := range []*Expected{exp, trusted} {
					if e.Failed() {
						t.Fatalf("c2patool failed on a signed fixture: %s", e.C2patoolError)
					}
					if len(e.ManifestLabels()) == 0 || len(e.Codes()) == 0 {
						t.Errorf("no manifests or status codes in oracle output")
					}
					if _, ok := e.Manifests[e.ActiveManifest]; !ok {
						t.Errorf("active manifest %q not in manifests", e.ActiveManifest)
					}
				}
			case Unsigned:
				if !exp.Failed() {
					t.Errorf("c2patool found a manifest in an unsigned fixture")
				}
			case Broken:
				if !exp.Failed() && exp.ValidationResults == nil {
					t.Errorf("broken fixture has neither an error nor validation results")
				}
			}
		})
	}
}
