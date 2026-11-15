// Command ghaction is the program behind the C2paSeal GitHub Action
// (action.yml at the repository root). It reads the action's inputs from
// INPUT_* environment variables, signs or verifies the files, and writes the
// outputs, a job summary and a JSON Lines report.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func main() {
	os.Exit(run(os.Getenv, os.Stdout))
}

// inputs are the action's inputs (see action.yml).
type inputs struct {
	command    string
	files      []string
	cert, key  string
	certPEM    string
	keyPEM     string
	outDir     string
	inPlace    bool
	title      string
	sourceType string
	tsa        string
	noHistory  bool
	trust      []string
	failOn     string
}

func readInputs(env func(string) string) (*inputs, error) {
	get := func(name string) string {
		return strings.TrimSpace(env("INPUT_" + strings.ToUpper(strings.ReplaceAll(name, " ", "_"))))
	}
	lines := func(name string) []string {
		var out []string
		for _, l := range strings.Split(get(name), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	boolean := func(name string) (bool, error) {
		switch strings.ToLower(get(name)) {
		case "", "false":
			return false, nil
		case "true":
			return true, nil
		}
		return false, fmt.Errorf("input %s: want true or false, got %q", name, get(name))
	}
	in := &inputs{
		command:    strings.ToLower(get("command")),
		files:      lines("files"),
		cert:       get("cert"),
		key:        get("key"),
		certPEM:    env("INPUT_CERT-PEM"),
		keyPEM:     env("INPUT_KEY-PEM"),
		outDir:     get("out-dir"),
		title:      get("title"),
		sourceType: get("source-type"),
		tsa:        get("tsa"),
		trust:      lines("trust"),
		failOn:     strings.ToLower(get("fail-on")),
	}
	var err error
	if in.inPlace, err = boolean("in-place"); err != nil {
		return nil, err
	}
	if in.noHistory, err = boolean("no-history"); err != nil {
		return nil, err
	}
	if in.command != "sign" && in.command != "verify" {
		return nil, fmt.Errorf("input command: want sign or verify, got %q", in.command)
	}
	if len(in.files) == 0 {
		return nil, errors.New("input files is empty")
	}
	if in.outDir == "" {
		in.outDir = "c2paseal-signed"
	}
	if in.failOn == "" {
		in.failOn = "invalid"
	}
	switch in.failOn {
	case "invalid", "untrusted", "never":
	default:
		return nil, fmt.Errorf("input fail-on: want invalid, untrusted or never, got %q", in.failOn)
	}
	return in, nil
}

// record is one line of the JSON Lines report.
type record struct {
	File     string   `json:"file"`
	Output   string   `json:"output,omitempty"`   // sign: the signed file
	Parent   bool     `json:"parent,omitempty"`   // sign: existing credentials kept as the parent
	State    string   `json:"state,omitempty"`    // verify: Invalid, Valid or Trusted
	Failures []string `json:"failures,omitempty"` // verify: failure status codes
	Error    string   `json:"error,omitempty"`
}

// run is main, testable: it returns the exit code.
func run(env func(string) string, stdout io.Writer) int {
	in, err := readInputs(env)
	if err != nil {
		fmt.Fprintf(stdout, "::error::%s\n", escape(err.Error()))
		return 1
	}
	files, err := expand(in.files)
	if err != nil {
		fmt.Fprintf(stdout, "::error::%s\n", escape(err.Error()))
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintf(stdout, "::error::no images match input files (%s)\n", escape(strings.Join(in.files, ", ")))
		return 1
	}
	var recs []record
	fail := false
	if in.command == "sign" {
		recs, err = signAll(in, files)
		if err != nil {
			fmt.Fprintf(stdout, "::error::%s\n", escape(err.Error()))
			return 1
		}
		for _, r := range recs {
			if r.Error != "" {
				fail = true
			}
		}
	} else {
		recs, err = verifyAll(in, files)
		if err != nil {
			fmt.Fprintf(stdout, "::error::%s\n", escape(err.Error()))
			return 1
		}
		for _, r := range recs {
			switch {
			case in.failOn == "never":
			case r.State == "Invalid" || r.Error != "":
				fail = true
			case in.failOn == "untrusted" && r.State != "Trusted":
				fail = true
			}
		}
	}
	for _, r := range recs {
		fmt.Fprintln(stdout, logLine(in.command, r))
		if r.Error != "" {
			fmt.Fprintf(stdout, "::error file=%s::%s\n", escapeProp(r.File), escape(r.Error))
		} else if r.State == "Invalid" && in.failOn != "never" {
			fmt.Fprintf(stdout, "::error file=%s::C2PA manifest invalid: %s\n", escapeProp(r.File), escape(strings.Join(r.Failures, ", ")))
		}
	}
	if err := writeResults(env, in.command, recs); err != nil {
		fmt.Fprintf(stdout, "::error::%s\n", escape(err.Error()))
		return 1
	}
	if fail {
		return 1
	}
	return 0
}

// expand turns the files input (paths, folders and globs, where ** matches
// any number of folders) into the sorted list of images. Folders give
// their images, recursively.
func expand(patterns []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = filepath.ToSlash(filepath.Clean(p))
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	walk := func(root string, keep func(string) bool) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != root && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir // .git and the like
				}
				return nil
			}
			if keep(filepath.ToSlash(p)) {
				add(p)
			}
			return nil
		})
	}
	for _, pat := range patterns {
		pat = filepath.ToSlash(pat)
		if !strings.ContainsAny(pat, "*?[") {
			st, err := os.Stat(pat)
			if err != nil {
				return nil, fmt.Errorf("files: %w", err)
			}
			if st.IsDir() {
				if err := walk(pat, isImage); err != nil {
					return nil, fmt.Errorf("files: %w", err)
				}
			} else {
				add(pat) // named explicitly: kept whatever its extension
			}
			continue
		}
		if _, err := path.Match(pat, ""); err != nil {
			return nil, fmt.Errorf("files: bad pattern %q: %w", pat, err)
		}
		root := globRoot(pat)
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := walk(root, func(p string) bool {
			return isImage(p) && match(pat, strings.TrimPrefix(p, "./"))
		})
		if err != nil {
			return nil, fmt.Errorf("files: %w", err)
		}
	}
	sort.Strings(out)
	return out, nil
}

// globRoot is the folder before a pattern's first wildcard.
func globRoot(pat string) string {
	parts := strings.Split(pat, "/")
	var fixed []string
	for _, p := range parts {
		if strings.ContainsAny(p, "*?[") {
			break
		}
		fixed = append(fixed, p)
	}
	if len(fixed) == 0 {
		return "."
	}
	if len(fixed) == 1 && fixed[0] == "" {
		return "/"
	}
	return strings.Join(fixed, "/")
}

// match reports whether name matches pat, segment by segment, where a **
// segment matches zero or more segments.
func match(pat, name string) bool {
	pat = strings.TrimPrefix(pat, "./")
	return matchParts(strings.Split(pat, "/"), strings.Split(name, "/"))
}

func matchParts(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if matchParts(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], name[0]); !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

func isImage(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".avif":
		return true
	}
	return false
}

func signAll(in *inputs, files []string) ([]record, error) {
	opts, err := signOptions(in)
	if err != nil {
		return nil, err
	}
	var recs []record
	for _, f := range files {
		r := record{File: f, Output: f}
		if !in.inPlace {
			r.Output = filepath.ToSlash(filepath.Join(in.outDir, outName(f)))
		}
		b, err := os.ReadFile(f)
		if err == nil {
			var s *sign.Signed
			if s, err = sign.Asset(b, opts); err == nil {
				r.Parent = s.Parent
				if err = os.MkdirAll(filepath.Dir(r.Output), 0o755); err == nil {
					err = os.WriteFile(r.Output, s.File, 0o644)
				}
			}
		}
		if err != nil {
			r.Error = err.Error()
			r.Output = ""
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// outName is where a file goes under out-dir: its path relative to the
// workspace, or its base name if it is outside it.
func outName(f string) string {
	if filepath.IsAbs(f) || strings.HasPrefix(f, "../") || f == ".." {
		return filepath.Base(f)
	}
	return f
}

func signOptions(in *inputs) (*sign.Options, error) {
	var chainPEM []byte
	switch {
	case in.certPEM != "" && in.cert != "":
		return nil, errors.New("give cert or cert-pem, not both")
	case in.certPEM != "":
		chainPEM = []byte(in.certPEM)
	case in.cert != "":
		b, err := os.ReadFile(in.cert)
		if err != nil {
			return nil, fmt.Errorf("cert: %w", err)
		}
		chainPEM = b
	default:
		return nil, errors.New("sign needs cert or cert-pem")
	}
	opts := &sign.Options{
		Title:             in.title,
		DigitalSourceType: in.sourceType,
		TSAURL:            in.tsa,
		NoHistory:         in.noHistory,
	}
	switch {
	case in.keyPEM != "" && in.key != "":
		return nil, errors.New("give key or key-pem, not both")
	case in.keyPEM != "":
		chain, signer, err := c2paseal.ParseSigner(chainPEM, []byte(in.keyPEM))
		if err != nil {
			return nil, fmt.Errorf("cert-pem / key-pem: %w", err)
		}
		opts.Chain, opts.Signer = chain, signer
	case in.key != "":
		chain, err := loadChain(in.cert, chainPEM)
		if err != nil {
			return nil, err
		}
		signer, err := sign.OpenKey(context.Background(), in.key)
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
		opts.Chain, opts.Signer = chain, signer
	default:
		return nil, errors.New("sign needs key or key-pem")
	}
	return opts, nil
}

// loadChain reads the certificate chain from the cert file, or from
// cert-pem through a temporary file (LoadChain reads files).
func loadChain(path string, pemBytes []byte) ([]*x509.Certificate, error) {
	if path == "" {
		f, err := os.CreateTemp("", "c2paseal-chain-*.pem")
		if err != nil {
			return nil, fmt.Errorf("cert-pem: %w", err)
		}
		defer os.Remove(f.Name())
		_, err = f.Write(pemBytes)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("cert-pem: %w", err)
		}
		path = f.Name()
	}
	chain, err := c2paseal.LoadChain(path)
	if err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	return chain, nil
}

func verifyAll(in *inputs, files []string) ([]record, error) {
	opts := &verify.Options{}
	for _, t := range in.trust {
		a, err := c2paseal.LoadTrustAnchors(t)
		if err != nil {
			return nil, fmt.Errorf("trust: %w", err)
		}
		opts.TrustAnchors = append(opts.TrustAnchors, a...)
	}
	var recs []record
	for _, f := range files {
		res := c2paseal.VerifyFile(f, opts)
		r := record{File: f, State: string(res.State())}
		for _, s := range res.Statuses() {
			if s.Kind() == verify.Failure {
				r.Failures = append(r.Failures, s.Code)
			}
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func logLine(command string, r record) string {
	switch {
	case r.Error != "":
		return fmt.Sprintf("%s: error: %s", r.File, r.Error)
	case command == "sign":
		s := fmt.Sprintf("%s: signed -> %s", r.File, r.Output)
		if r.Parent {
			s += " (existing credentials kept as the parent)"
		}
		return s
	case len(r.Failures) > 0:
		return fmt.Sprintf("%s: %s (%s)", r.File, r.State, strings.Join(r.Failures, ", "))
	}
	return fmt.Sprintf("%s: %s", r.File, r.State)
}

// writeResults writes the report, the outputs and the job summary.
func writeResults(env func(string) string, command string, recs []record) error {
	dir := env("RUNNER_TEMP")
	if dir == "" {
		dir = os.TempDir()
	}
	report := filepath.Join(dir, "c2paseal-report.jsonl")
	var sb strings.Builder
	for _, r := range recs {
		b, _ := json.Marshal(r)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(report, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("report: %w", err)
	}

	counts := map[string]int{}
	var signed []string
	for _, r := range recs {
		switch {
		case r.Error != "":
			counts["error"]++
		case command == "sign":
			counts["signed"]++
			signed = append(signed, r.Output)
		default:
			counts[strings.ToLower(r.State)]++
		}
	}
	if p := env("GITHUB_OUTPUT"); p != "" {
		var o strings.Builder
		fmt.Fprintf(&o, "report=%s\n", report)
		fmt.Fprintf(&o, "signed-files<<C2PASEAL_EOF\n%s\nC2PASEAL_EOF\n", strings.Join(signed, "\n"))
		for _, k := range []string{"signed", "trusted", "valid", "invalid", "error"} {
			fmt.Fprintf(&o, "%s-count=%d\n", k, counts[k])
		}
		if err := appendFile(p, o.String()); err != nil {
			return fmt.Errorf("GITHUB_OUTPUT: %w", err)
		}
	}
	if p := env("GITHUB_STEP_SUMMARY"); p != "" {
		if err := appendFile(p, summary(command, recs, counts)); err != nil {
			return fmt.Errorf("GITHUB_STEP_SUMMARY: %w", err)
		}
	}
	return nil
}

func summary(command string, recs []record, counts map[string]int) string {
	var s strings.Builder
	if command == "sign" {
		fmt.Fprintf(&s, "### C2paSeal: signed %d of %d files\n\n| File | Signed file | Note |\n|---|---|---|\n", counts["signed"], len(recs))
		for _, r := range recs {
			note := ""
			switch {
			case r.Error != "":
				note = "error: " + r.Error
			case r.Parent:
				note = "existing credentials kept as the parent"
			}
			fmt.Fprintf(&s, "| `%s` | %s | %s |\n", cell(r.File), code(r.Output), cell(note))
		}
	} else {
		fmt.Fprintf(&s, "### C2paSeal: verified %d files\n\nTrusted %d · Valid %d · Invalid %d · Errors %d\n\n| File | State | Failures |\n|---|---|---|\n",
			len(recs), counts["trusted"], counts["valid"], counts["invalid"], counts["error"])
		for _, r := range recs {
			fmt.Fprintf(&s, "| `%s` | %s | %s |\n", cell(r.File), r.State, cell(strings.Join(r.Failures, ", ")+r.Error))
		}
		if counts["valid"] > 0 {
			s.WriteString("\nValid means the credentials are intact but the signer is not on the trust list given in `trust`.\n")
		}
	}
	s.WriteString("\n")
	return s.String()
}

func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + cell(s) + "`"
}

func cell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "`", "'").Replace(s)
}

func appendFile(p, s string) error {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// escape encodes a workflow command message.
func escape(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// escapeProp encodes a workflow command property, such as file=.
func escapeProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
