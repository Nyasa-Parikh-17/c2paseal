package sign

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// storeOf decodes a signed file's embedded manifest store.
func storeOf(t *testing.T, file []byte) []*manifest.Manifest {
	t.Helper()
	_, root, err := asset.Extract(file)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

// decodedIngredient is the part of our ingredient assertion the tests read.
type decodedIngredient struct {
	Relationship   string             `cbor:"relationship"`
	Format         string             `cbor:"dc:format"`
	InstanceID     string             `cbor:"instanceID"`
	ActiveManifest manifest.HashedURI `cbor:"activeManifest"`
	ClaimSignature manifest.HashedURI `cbor:"claimSignature"`
	Results        struct {
		Active struct {
			Failure []struct {
				Code string `cbor:"code"`
			} `cbor:"failure"`
		} `cbor:"activeManifest"`
	} `cbor:"validationResults"`
}

func ingredientOf(t *testing.T, m *manifest.Manifest) decodedIngredient {
	t.Helper()
	a := m.Assertion(LabelIngredient)
	if a == nil {
		t.Fatalf("%s has no %s assertion", m.Label, LabelIngredient)
	}
	var ing decodedIngredient
	if err := cbormode.Dec.Unmarshal(a.Box.Contents()[0].Payload, &ing); err != nil {
		t.Fatal(err)
	}
	return ing
}

// checkChild checks a re-signed file against its parent: the parent's
// manifests come first, byte for byte, and the new active manifest records
// the parent's active manifest as a parentOf ingredient, referenced by a
// leading c2pa.opened action.
func checkChild(t *testing.T, name string, parentFile, child []byte) {
	t.Helper()
	checkSigned(t, name, child)
	pm, cm := storeOf(t, parentFile), storeOf(t, child)
	if len(cm) != len(pm)+1 {
		t.Fatalf("%s: %d manifests, want %d", name, len(cm), len(pm)+1)
	}
	for i := range pm {
		if !bytes.Equal(pm[i].Box.Raw, cm[i].Box.Raw) {
			t.Errorf("%s: parent manifest %d changed", name, i)
		}
	}
	prev, active := pm[len(pm)-1], cm[len(cm)-1]
	ing := ingredientOf(t, active)
	if ing.Relationship != "parentOf" || ing.ActiveManifest.URL != verify.ManifestURL(prev.Label) ||
		ing.ClaimSignature.URL != verify.SignatureURL(prev) || ing.InstanceID != prev.Claim.InstanceID {
		t.Errorf("%s: ingredient %+v does not describe parent %s", name, ing, prev.Label)
	}
	if sum, _ := manifest.HashBox("sha256", prev.Box); !bytes.Equal(sum, ing.ActiveManifest.Hash) {
		t.Errorf("%s: activeManifest hash does not match the parent manifest", name)
	}
	acts, ok := active.Assertion(assertion.LabelActionsV2).Value.(*assertion.Actions)
	if !ok || len(acts.Actions) == 0 || acts.Actions[0].Action != "c2pa.opened" {
		t.Fatalf("%s: first action is not c2pa.opened", name)
	}
	refs, _ := acts.Actions[0].Parameters["ingredients"].([]any)
	if len(refs) != 1 {
		t.Errorf("%s: c2pa.opened ingredients %v", name, acts.Actions[0].Parameters)
	}
}

// TestIngredientChain re-signs our own output twice, for chains of two and
// three manifests, in both formats.
func TestIngredientChain(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	for _, name := range []string{"small.jpg", "small.png"} {
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(dir, "unsigned", name))
			if err != nil {
				t.Fatal(err)
			}
			gen1, err := Asset(in, &Options{Chain: chain, Signer: key})
			if err != nil || gen1.Parent {
				t.Fatalf("first signature: %v (parent %v)", err, gen1 != nil && gen1.Parent)
			}
			prev := gen1.File
			for gen := 2; gen <= 3; gen++ {
				s, err := Asset(prev, &Options{Chain: chain, Signer: key,
					Actions: []assertion.Action{{Action: "c2pa.color_adjustments"}}})
				if err != nil {
					t.Fatalf("generation %d: %v", gen, err)
				}
				if !s.Parent {
					t.Errorf("generation %d: Parent not reported", gen)
				}
				checkChild(t, name, prev, s.File)
				// As in c2patool's own chain (signed/edited.jpg), the one
				// delta is the success code for the ingredient hash.
				r := verify.File(s.File, nil)
				if len(r.IngredientDeltas) != 1 || len(r.IngredientDeltas[0].ValidationDeltas) != 1 ||
					r.IngredientDeltas[0].ValidationDeltas[0].Code != verify.IngredientManifestValidated {
					t.Errorf("generation %d: ingredient deltas %+v", gen, r.IngredientDeltas)
				}
				prev = s.File
			}
		})
	}
}

// TestResignC2patoolChain keeps c2patool's two-manifest edited.jpg (itself
// an ingredient chain) as the parent of a third manifest.
func TestResignC2patoolChain(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	for _, f := range []string{"signed/edited.jpg", "signed/ts.png", "signed/titled-ts.jpg"} {
		in, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		out, err := Asset(in, &Options{Chain: chain, Signer: key})
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		checkChild(t, f, in, out.File)
	}
}

// TestClaimSignatureHashConvention checks how we hash the claimSignature
// reference against c2pa-rs: in c2patool's edited.jpg, the ingredient's
// claimSignature hash must be the hash of the parent's signature box,
// computed as manifest.HashBox does.
func TestClaimSignatureHashConvention(t *testing.T) {
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "signed", "edited.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	ms := storeOf(t, in)
	ing := ingredientOf(t, ms[1])
	if ing.ClaimSignature.URL != verify.SignatureURL(ms[0]) {
		t.Fatalf("fixture claimSignature URL %s", ing.ClaimSignature.URL)
	}
	sum, _ := manifest.HashBox("sha256", ms[0].SignatureBox)
	if !bytes.Equal(sum, ing.ClaimSignature.Hash) {
		t.Errorf("HashBox(signature box) differs from c2patool's claimSignature hash")
	}
	sum, _ = manifest.HashBox("sha256", ms[0].Box)
	if !bytes.Equal(sum, ing.ActiveManifest.Hash) {
		t.Errorf("HashBox(manifest box) differs from c2patool's activeManifest hash")
	}
}

// TestTamperedParent records an invalid parent: its failure is kept in the
// ingredient's validation results, and the new manifest is valid.
func TestTamperedParent(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	in, err := os.ReadFile(filepath.Join(dir, "broken", "data-flip.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := JPEG(in, &Options{Chain: chain, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, "data-flip.jpg re-signed", out)
	ms := storeOf(t, out)
	var codes []string
	for _, f := range ingredientOf(t, ms[len(ms)-1]).Results.Active.Failure {
		codes = append(codes, f.Code)
	}
	if !slices.Contains(codes, verify.AssertionDataHashMismatch) {
		t.Errorf("recorded parent failures %q, want %s among them", codes, verify.AssertionDataHashMismatch)
	}
}

func TestParentOptions(t *testing.T) {
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	signed, err := os.ReadFile(filepath.Join(dir, "signed", "small.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	broken, err := os.ReadFile(filepath.Join(dir, "broken", "bad-jumbf-length.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	base := Options{Chain: chain, Signer: key}
	with := func(f func(*Options)) *Options { o := base; f(&o); return &o }

	for _, tc := range []struct {
		name string
		in   []byte
		opts *Options
		want error
	}{
		{"created with parent", signed, with(func(o *Options) {
			o.Actions = []assertion.Action{{Action: "c2pa.created", DigitalSourceType: "x"}}
		}), ErrBadActions},
		{"source type with parent", signed, with(func(o *Options) { o.DigitalSourceType = "x" }), ErrBadActions},
		{"placed with parent", signed, with(func(o *Options) { o.Actions = []assertion.Action{{Action: "c2pa.placed"}} }), ErrBadActions},
		{"unreadable parent", broken, &base, ErrParent},
		{"unreadable parent, no history", broken, with(func(o *Options) { o.NoHistory = true }), nil},
		{"created, no history", signed, with(func(o *Options) {
			o.NoHistory = true
			o.Actions = []assertion.Action{{Action: "c2pa.created", DigitalSourceType: "x"}}
		}), nil},
		{"explicit opened", signed, with(func(o *Options) {
			o.Actions = []assertion.Action{{Action: "c2pa.opened", Parameters: map[string]any{"description": "kept"}}, {Action: "c2pa.edited"}}
		}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := JPEG(tc.in, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if err == nil {
				checkSigned(t, tc.name, out)
			}
		})
	}

	// An explicit c2pa.opened keeps its own parameters next to ingredients.
	out, err := JPEG(signed, with(func(o *Options) {
		o.Actions = []assertion.Action{{Action: "c2pa.opened", Parameters: map[string]any{"description": "kept"}}}
	}))
	if err != nil {
		t.Fatal(err)
	}
	ms := storeOf(t, out)
	acts := ms[len(ms)-1].Assertion(assertion.LabelActionsV2).Value.(*assertion.Actions)
	if p := acts.Actions[0].Parameters; p["description"] != "kept" || p["ingredients"] == nil || len(acts.Actions) != 1 {
		t.Errorf("opened action %+v", acts.Actions)
	}
}

// c2patoolReport runs c2patool --detailed on path and returns its report.
type c2patoolReport struct {
	Active    string                     `json:"active_manifest"`
	Manifests map[string]json.RawMessage `json:"manifests"`
	State     string                     `json:"validation_state"`
	Results   struct {
		Active struct {
			Success []struct{ Code string } `json:"success"`
			Failure []struct{ Code string } `json:"failure"`
		} `json:"activeManifest"`
		Deltas []struct {
			Deltas struct {
				Failure []struct{ Code string } `json:"failure"`
			} `json:"validationDeltas"`
		} `json:"ingredientDeltas"`
	} `json:"validation_results"`
}

func (r *c2patoolReport) failures() []string {
	var out []string
	for _, f := range r.Results.Active.Failure {
		out = append(out, f.Code)
	}
	for _, d := range r.Results.Deltas {
		for _, f := range d.Deltas.Failure {
			out = append(out, f.Code)
		}
	}
	return out
}

// needC2patool skips the test without c2patool and pins its settings to an
// empty file.
func needC2patool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("c2patool"); err != nil {
		t.Skip("c2patool not on PATH")
	}
	settings := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(settings, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("C2PATOOL_SETTINGS", settings)
}

func runC2patool(t *testing.T, path string, trusted bool) *c2patoolReport {
	t.Helper()
	args := []string{path, "--detailed"}
	if trusted {
		args = append(args, "trust", "--trust_anchors", "../testdata/pki/trust-anchors.pem")
	}
	b, err := exec.Command("c2patool", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("c2patool %s: %v\n%s", path, err, ee.Stderr)
		}
		t.Fatalf("c2patool %s: %v", path, err)
	}
	var rep c2patoolReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	return &rep
}

// TestC2patoolIngredientChain: c2patool accepts our chains of two and three
// manifests, with no failure beyond signingCredential.untrusted (none with
// the test root trusted), and sees every manifest.
func TestC2patoolIngredientChain(t *testing.T) {
	needC2patool(t)
	chain, key := testPKI(t)
	dir, _ := fixtures.Dir()
	for _, name := range []string{"small.jpg", "small.png", "large.jpg", "large.png"} {
		prev, err := os.ReadFile(filepath.Join(dir, "unsigned", name))
		if err != nil {
			t.Fatal(err)
		}
		for gen := 1; gen <= 3; gen++ {
			out, err := Asset(prev, &Options{Chain: chain, Signer: key})
			if err != nil {
				t.Fatal(err)
			}
			prev = out.File
			if gen == 1 {
				continue
			}
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, out.File, 0o644); err != nil {
				t.Fatal(err)
			}
			for _, trusted := range []bool{false, true} {
				rep := runC2patool(t, path, trusted)
				wantState, wantFail := "Valid", []string{verify.SigningCredentialUntrusted}
				if trusted {
					wantState, wantFail = "Trusted", nil
				}
				if rep.State != wantState || !slices.Equal(rep.failures(), wantFail) || len(rep.Manifests) != gen {
					t.Errorf("%s generation %d (trusted %v): c2patool state %s, failures %q, %d manifests",
						name, gen, trusted, rep.State, rep.failures(), len(rep.Manifests))
				}
			}
		}
	}
}
