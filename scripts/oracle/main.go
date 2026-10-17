// Command oracle runs `c2patool <file> --detailed` on every fixture and
// writes the output next to it:
//
//	<file>.expected.json          default trust settings (test PKI untrusted)
//	<file>.trusted.expected.json  with testdata/pki/trust-anchors.pem trusted
//
// When c2patool fails (no manifest, unparseable file) the file holds
// {"c2patool_error": "<stderr>", "exit_code": N} instead. Output is never
// edited afterwards.
//
// Usage: go run ./scripts/oracle <testdata-dir>
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var dirs = []string{"unsigned", "signed", "broken", "samples"}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: oracle <testdata-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(1)
	}
}

func run(root string) error {
	// Relative path: c2patool reads "C:/..." as a URL with scheme "c".
	anchors := filepath.ToSlash(filepath.Join(root, "pki", "trust-anchors.pem"))
	for _, d := range dirs {
		files, err := filepath.Glob(filepath.Join(root, d, "*"))
		if err != nil {
			return err
		}
		for _, f := range files {
			if !isImage(f) {
				continue
			}
			if err := write(f+".expected.json", f); err != nil {
				return err
			}
			if err := write(f+".trusted.expected.json", f, "trust", "--trust_anchors", anchors); err != nil {
				return err
			}
			fmt.Println("oracle:", f)
		}
	}
	return nil
}

func isImage(f string) bool {
	switch strings.ToLower(filepath.Ext(f)) {
	case ".jpg", ".jpeg", ".png":
		return true
	}
	return false
}

func write(out, file string, extra ...string) error {
	cmd := exec.Command("c2patool", append([]string{file, "--detailed"}, extra...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()

	var exit *exec.ExitError
	switch {
	case err == nil && json.Valid(stdout.Bytes()):
		return os.WriteFile(out, stdout.Bytes(), 0o644)
	case err == nil:
		return fmt.Errorf("%s: c2patool printed invalid JSON", file)
	case errors.As(err, &exit):
		b, err := json.MarshalIndent(struct {
			Error    string `json:"c2patool_error"`
			ExitCode int    `json:"exit_code"`
		}{strings.TrimSpace(stderr.String()), exit.ExitCode()}, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(out, append(b, '\n'), 0o644)
	default:
		return fmt.Errorf("run c2patool on %s: %w", file, err)
	}
}
