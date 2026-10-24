// Command mvp-evidence signs every unsigned JPEG fixture with C2paSeal and
// records what c2patool (and C2paSeal) say about the result, in
// testdata/mvp-evidence/:
//
//	<name>.signed.jpg              the file C2paSeal signed (TEST ONLY PKI)
//	<name>.c2patool.json           c2patool <file> --detailed
//	<name>.c2patool.trusted.json   the same with testdata/pki/trust-anchors.pem trusted
//	<name>.c2paseal.json           c2paseal verify --json, default trust
//	README.md                      summary table
//
// c2patool output is saved exactly as printed. Run from the repo root:
//
//	go run ./scripts/mvp-evidence
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

const (
	outDir  = "testdata/mvp-evidence"
	anchors = "testdata/pki/trust-anchors.pem" // relative: c2patool reads "C:/..." as a URL
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mvp-evidence:", err)
		os.Exit(1)
	}
}

type row struct {
	name                      string
	toolState, toolFailures   string
	trustState, trustFailures string
	sealState, sealFailures   string
}

func run() error {
	if _, err := exec.LookPath("c2patool"); err != nil {
		return fmt.Errorf("c2patool not on PATH: %w", err)
	}
	// Pin c2patool to an empty settings file so local config cannot change it.
	settings, err := os.CreateTemp("", "c2patool-settings-*.toml")
	if err != nil {
		return err
	}
	settings.Close()
	defer os.Remove(settings.Name())
	os.Setenv("C2PATOOL_SETTINGS", settings.Name())

	chain, key, err := c2paseal.LoadSigner("testdata/pki/leaf-chain.pem", "testdata/pki/leaf.key")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	inputs, err := filepath.Glob("testdata/unsigned/*.jpg")
	if err != nil || len(inputs) == 0 {
		return fmt.Errorf("no unsigned JPEG fixtures (%v)", err)
	}

	var rows []row
	for _, in := range inputs {
		name := strings.TrimSuffix(filepath.Base(in), ".jpg")
		signed := filepath.ToSlash(filepath.Join(outDir, name+".signed.jpg"))
		if err := c2paseal.Sign(in, signed, &c2paseal.SignOptions{Chain: chain, Signer: key, Title: name + ".jpg"}); err != nil {
			return fmt.Errorf("sign %s: %w", in, err)
		}
		r := row{name: name + ".jpg"}
		if r.toolState, r.toolFailures, err = c2patool(signed, "", strings.TrimSuffix(signed, ".signed.jpg")+".c2patool.json"); err != nil {
			return err
		}
		if r.trustState, r.trustFailures, err = c2patool(signed, "trust", strings.TrimSuffix(signed, ".signed.jpg")+".c2patool.trusted.json"); err != nil {
			return err
		}
		res := c2paseal.VerifyFile(signed, nil)
		b, err := json.MarshalIndent(struct {
			Results *verify.Result `json:"validation_results"`
			State   verify.State   `json:"validation_state"`
		}{res, res.State()}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(strings.TrimSuffix(signed, ".signed.jpg")+".c2paseal.json", append(b, '\n'), 0o644); err != nil {
			return err
		}
		r.sealState = string(res.State())
		var fails []string
		for _, s := range res.Statuses() {
			if s.Kind() == verify.Failure {
				fails = append(fails, s.Code)
			}
		}
		r.sealFailures = list(fails)
		rows = append(rows, r)
		fmt.Println("evidence:", signed)
	}
	return writeReadme(rows)
}

// c2patool runs c2patool --detailed (with the test root trusted if mode is
// "trust"), saves its output unchanged and returns the state and failures.
func c2patool(file, mode, out string) (state, failures string, err error) {
	args := []string{file, "--detailed"}
	if mode == "trust" {
		args = append(args, "trust", "--trust_anchors", anchors)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("c2patool", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("c2patool %v: %w: %s", args, err, stderr.String())
	}
	if err := os.WriteFile(out, stdout.Bytes(), 0o644); err != nil {
		return "", "", err
	}
	var rep struct {
		State   string `json:"validation_state"`
		Results struct {
			Active struct {
				Failure []struct{ Code string } `json:"failure"`
			} `json:"activeManifest"`
		} `json:"validation_results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return "", "", fmt.Errorf("c2patool output for %s: %w", file, err)
	}
	var codes []string
	for _, f := range rep.Results.Active.Failure {
		codes = append(codes, f.Code)
	}
	return rep.State, list(codes), nil
}

func list(codes []string) string {
	if len(codes) == 0 {
		return "none"
	}
	return strings.Join(codes, ", ")
}

func writeReadme(rows []row) error {
	version, _ := exec.Command("c2patool", "--version").Output()
	var b strings.Builder
	fmt.Fprintf(&b, `# MVP evidence

Unsigned JPEG fixtures signed by **C2paSeal** (ES256, TEST ONLY PKI in
`+"`testdata/pki`"+`), then checked by c2patool and by C2paSeal itself.
Regenerate with `+"`go run ./scripts/mvp-evidence`"+` from the repo root.

- Generated: %s
- Validator: %s
- `+"`*.c2patool*.json`"+` are c2patool's output, saved unedited.

The test certificates chain to a root nobody trusts, so by default the only
failure is `+"`signingCredential.untrusted`"+` (state `+"`Valid`"+`). With the test root
trusted there are no failures (state `+"`Trusted`"+`).

| File | c2patool (default trust) | c2patool failures | c2patool (test root trusted) | failures | C2paSeal verify | C2paSeal failures |
|---|---|---|---|---|---|---|
`, time.Now().UTC().Format(time.DateOnly), strings.TrimSpace(string(version)))
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			r.name, r.toolState, r.toolFailures, r.trustState, r.trustFailures, r.sealState, r.sealFailures)
	}
	return os.WriteFile(filepath.Join(outDir, "README.md"), []byte(b.String()), 0o644)
}
