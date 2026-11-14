package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// mode is a trust configuration.
type mode string

const (
	// modeDefault: each tool's own default trust (C2paSeal: none; c2patool:
	// none; c2pa-mcp: its embedded C2PA trust list).
	modeDefault mode = "default"
	// modeTrusted: the TEST ONLY root (testdata/pki/trust-anchors.pem) is
	// the signing and time-stamping trust anchor.
	modeTrusted mode = "trusted"
)

var modes = []mode{modeDefault, modeTrusted}

// toolInfo describes a tool in the report.
type toolInfo struct {
	Name      string
	Version   string
	Installed bool
	Note      string
}

// outcome is what one tool said about one file in one mode.
type outcome struct {
	Err      string   // the tool could not produce statuses
	Native   string   // the tool's own verdict, as it prints it
	Failure  []string // failure status codes, active manifest
	Info     []string
	Success  []string
	State    string // derived with one rule for every tool (see deriveState)
	Skipped  bool   // tool not installed
	ExitCode int
}

type tool interface {
	info() toolInfo
	run(path string, m mode) outcome
}

// deriveState applies c2pa-rs's validation-state rule to a tool's failure
// codes, so tools with different native verdicts can be compared:
// any failure other than signingCredential.untrusted → Invalid; no failures
// and signingCredential.trusted → Trusted; otherwise Valid.
func deriveState(o *outcome) {
	if o.Skipped {
		o.State = "-"
		return
	}
	if o.Err != "" {
		o.State = "error"
		return
	}
	for _, f := range o.Failure {
		if f != verify.SigningCredentialUntrusted {
			o.State = "Invalid"
			return
		}
	}
	if len(o.Failure) == 0 && slices.Contains(o.Success, verify.SigningCredentialTrusted) {
		o.State = "Trusted"
		return
	}
	o.State = "Valid"
}

// --- C2paSeal ---

type c2paSealTool struct{ anchors string }

func newC2paSeal(td string) tool {
	return &c2paSealTool{anchors: filepath.Join(td, "pki", "trust-anchors.pem")}
}

func (c *c2paSealTool) info() toolInfo {
	return toolInfo{Name: "C2paSeal", Version: "this tree (in process)", Installed: true}
}

func (c *c2paSealTool) run(path string, m mode) outcome {
	// Like c2patool, read a sidecar and fetch a remote-only store
	// (VerifyFile does the first; FetchRemote turns on the second).
	opts := &verify.Options{FetchRemote: true}
	if m == modeTrusted {
		anchors, err := c2paseal.LoadTrustAnchors(c.anchors)
		if err != nil {
			return outcome{Err: err.Error()}
		}
		opts.TrustAnchors = anchors
	}
	r := c2paseal.VerifyFile(path, opts)
	var o outcome
	for _, s := range r.ActiveManifest {
		switch s.Kind() {
		case verify.Failure:
			o.Failure = append(o.Failure, s.Code)
		case verify.Informational:
			o.Info = append(o.Info, s.Code)
		default:
			o.Success = append(o.Success, s.Code)
		}
	}
	o.Native = string(r.State())
	deriveState(&o)
	return o
}

// --- external tools ---

// external runs a CLI with a timeout and returns stdout and the exit code.
func external(dir string, env []string, name string, args ...string) ([]byte, int, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.Output(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return nil, -1, errors.New("timed out after 60 s")
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
		err = nil
		if len(out) == 0 {
			err = errors.New(firstLine(withoutWarnings(stderr.String())))
		}
	}
	return out, code, err
}

// withoutWarnings drops "WARNING: ..." lines (Credentio prints them before
// the real error), so the reported error is the line that explains it.
func withoutWarnings(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "WARNING:") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// --- c2patool ---

type c2patoolTool struct {
	path, root, settings string
	version              string
}

func newC2patool(root, td string) tool {
	t := &c2patoolTool{root: root}
	p, err := exec.LookPath("c2patool")
	if err != nil {
		return t
	}
	t.path = p
	// An empty settings file so the user's own c2patool settings (trust
	// lists, verification options) do not leak into the results.
	f, err := os.CreateTemp("", "c2patool-settings-*.toml")
	if err == nil {
		f.Close()
		t.settings = f.Name()
	}
	if out, _, err := external(root, nil, p, "--version"); err == nil {
		t.version = strings.TrimSpace(string(out))
	}
	return t
}

func (c *c2patoolTool) info() toolInfo {
	return toolInfo{Name: "c2patool", Version: c.version, Installed: c.path != "",
		Note: "the C2PA reference CLI, built on c2pa-rs"}
}

func (c *c2patoolTool) run(path string, m mode) outcome {
	if c.path == "" {
		o := outcome{Skipped: true}
		deriveState(&o)
		return o
	}
	args := []string{path, "--detailed"}
	if m == modeTrusted {
		// c2patool reads "C:/..." as a URL, so the anchors path is relative
		// to the repository root (the working directory).
		args = append(args, "trust", "--trust_anchors", filepath.ToSlash(filepath.Join("testdata", "pki", "trust-anchors.pem")))
	}
	out, code, err := external(c.root, []string{"C2PATOOL_SETTINGS=" + c.settings}, c.path, args...)
	o := outcome{ExitCode: code}
	if err != nil {
		o.Err = err.Error()
		deriveState(&o)
		return o
	}
	var rep struct {
		State   string `json:"validation_state"`
		Results struct {
			Active struct {
				Success       []struct{ Code string } `json:"success"`
				Informational []struct{ Code string } `json:"informational"`
				Failure       []struct{ Code string } `json:"failure"`
			} `json:"activeManifest"`
		} `json:"validation_results"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		o.Err = "unparseable output: " + firstLine(string(out))
		deriveState(&o)
		return o
	}
	for _, s := range rep.Results.Active.Success {
		o.Success = append(o.Success, s.Code)
	}
	for _, s := range rep.Results.Active.Informational {
		o.Info = append(o.Info, s.Code)
	}
	for _, s := range rep.Results.Active.Failure {
		o.Failure = append(o.Failure, s.Code)
	}
	o.Native = rep.State
	deriveState(&o)
	return o
}

// --- c2pa-mcp ---

type c2paMCPTool struct {
	path, anchors string
	version       string
}

func newC2paMCP(td string) tool {
	t := &c2paMCPTool{anchors: filepath.Join(td, "pki", "trust-anchors.pem")}
	p, err := exec.LookPath("c2pa-mcp")
	if err != nil {
		return t
	}
	t.path = p
	// The binary prints "dev" for --version when go-installed; read the
	// module versions from its build info instead.
	if bi, err := buildinfo.ReadFile(p); err == nil {
		lib := ""
		for _, d := range bi.Deps {
			if d.Path == "github.com/richardwooding/c2pa" {
				lib = d.Version
			}
		}
		t.version = fmt.Sprintf("%s (github.com/richardwooding/c2pa %s)", bi.Main.Version, lib)
	}
	return t
}

func (c *c2paMCPTool) info() toolInfo {
	return toolInfo{Name: "c2pa-mcp", Version: c.version, Installed: c.path != "",
		Note: "pure-Go CLI over github.com/richardwooding/c2pa (`verify --json`)"}
}

func (c *c2paMCPTool) run(path string, m mode) outcome {
	if c.path == "" {
		o := outcome{Skipped: true}
		deriveState(&o)
		return o
	}
	args := []string{"verify", path, "--json"}
	if m == modeTrusted {
		args = append(args, "--signing-trust", c.anchors, "--timestamp-trust", c.anchors)
	}
	out, code, err := external(filepath.Dir(path), nil, c.path, args...)
	o := outcome{ExitCode: code}
	if err != nil {
		o.Err = err.Error()
		deriveState(&o)
		return o
	}
	var rep struct {
		Valid    bool `json:"valid"`
		Statuses []struct {
			Code     string `json:"code"`
			Severity string `json:"severity"`
			URI      string `json:"uri"`
		} `json:"statuses"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		o.Err = "unparseable output: " + firstLine(string(out))
		deriveState(&o)
		return o
	}
	for _, s := range rep.Statuses {
		switch s.Severity {
		case "failure":
			o.Failure = append(o.Failure, s.Code)
		case "informational", "warning":
			o.Info = append(o.Info, s.Code)
		default:
			o.Success = append(o.Success, s.Code)
		}
	}
	o.Native = fmt.Sprintf("valid=%v", rep.Valid)
	deriveState(&o)
	return o
}

// --- Credentio ---

// Credentio (Google's C++ C2PA library) has no releases, so the binary is
// built from a pinned commit (see .github/workflows/interop.yml) and named
// by $CREDENTIO_VALIDATE or found as c2pa_validate on PATH. The commit is
// passed in $CREDENTIO_COMMIT. If the build failed, $CREDENTIO_BUILD_ERROR
// says why, and the tool is shown as not installed with that reason.
type credentioTool struct {
	path, anchors string
	commit, note  string
}

func newCredentio(td string) tool {
	t := &credentioTool{anchors: filepath.Join(td, "pki", "trust-anchors.pem"), commit: os.Getenv("CREDENTIO_COMMIT")}
	p := os.Getenv("CREDENTIO_VALIDATE")
	if p == "" {
		p, _ = exec.LookPath("c2pa_validate")
	}
	if p != "" {
		if _, err := os.Stat(p); err == nil {
			t.path = p
		}
	}
	if t.path == "" {
		t.note = os.Getenv("CREDENTIO_BUILD_ERROR")
	}
	return t
}

func (c *credentioTool) info() toolInfo {
	version := "commit " + c.commit
	if c.commit == "" {
		version = "unknown commit (set CREDENTIO_COMMIT)"
	}
	note := "Google's C++ C2PA library (`tools:c2pa_validate`, crJSON output); no releases, built from a pinned commit"
	if c.path == "" && c.note != "" {
		note += ". Not built: " + c.note
	}
	return toolInfo{Name: "Credentio", Version: version, Installed: c.path != "", Note: note}
}

func (c *credentioTool) run(path string, m mode) outcome {
	if c.path == "" {
		o := outcome{Skipped: true}
		deriveState(&o)
		return o
	}
	args := []string{"--asset=" + path, "--output_format=crjson"}
	if m == modeTrusted {
		args = append(args, "--claim_signer_trust="+c.anchors, "--tsa_trust="+c.anchors)
	}
	out, code, err := external(filepath.Dir(path), nil, c.path, args...)
	o := outcome{ExitCode: code}
	if err == nil && code != 0 {
		err = errors.New("exit code " + fmt.Sprint(code) + ": " + firstLine(string(out)))
	}
	if err != nil {
		o.Err = err.Error()
		deriveState(&o)
		return o
	}
	var rep struct {
		// The active manifest comes first (Credentio lists the store from
		// its last manifest backwards).
		Manifests []struct {
			Results struct {
				Success       []struct{ Code string } `json:"success"`
				Informational []struct{ Code string } `json:"informational"`
				Failure       []struct{ Code string } `json:"failure"`
			} `json:"validationResults"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		o.Err = "unparseable output: " + firstLine(string(out))
		deriveState(&o)
		return o
	}
	if len(rep.Manifests) == 0 {
		o.Err = "no manifests in the crJSON output"
		deriveState(&o)
		return o
	}
	a := rep.Manifests[0].Results
	for _, s := range a.Success {
		o.Success = append(o.Success, s.Code)
	}
	for _, s := range a.Informational {
		o.Info = append(o.Info, s.Code)
	}
	for _, s := range a.Failure {
		o.Failure = append(o.Failure, s.Code)
	}
	o.Native = "crJSON"
	deriveState(&o)
	return o
}
