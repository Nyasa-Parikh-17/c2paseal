package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// parsePaths parses flags that may appear before or after the path
// arguments and returns the paths (at least one).
func (c *command) parsePaths(args []string) ([]string, int) {
	var pos []string
	for {
		if err := c.fs.Parse(args); err != nil {
			return nil, c.parseErr(err)
		}
		if c.fs.NArg() == 0 {
			break
		}
		pos = append(pos, c.fs.Arg(0))
		args = c.fs.Args()[1:]
	}
	if len(pos) == 0 {
		fmt.Fprintf(c.stderr, "c2paseal %s: want a file or folder\n", c.fs.Name())
		c.fs.Usage()
		return nil, exitUsage
	}
	return pos, -1
}

// batchMode reports whether paths name more than one file: several paths,
// or a folder.
func batchMode(paths []string) bool {
	if len(paths) > 1 {
		return true
	}
	fi, err := os.Stat(paths[0])
	return err == nil && fi.IsDir()
}

// isImage reports whether a file name has an extension c2paseal reads.
func isImage(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".webp":
		return true
	}
	return false
}

// entry is one input of a batch run: a file to process, or a path that
// could not be listed.
type entry struct {
	path string
	err  error
}

// expand turns the command-line paths into the files to process, in order:
// a file stays as given; a folder gives its JPEG and PNG files sorted by
// name, and with recursive those of its subfolders too.
func expand(paths []string, recursive bool) []entry {
	var out []entry
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			out = append(out, entry{p, err})
			continue
		}
		if !fi.IsDir() {
			out = append(out, entry{path: p})
			continue
		}
		var files []string
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				out = append(out, entry{path, err})
				return nil
			}
			if d.IsDir() {
				if path != p && !recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && isImage(d.Name()) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			out = append(out, entry{p, err})
		}
		slices.Sort(files)
		for _, f := range files {
			out = append(out, entry{path: f})
		}
	}
	return out
}

// jsonLine writes v as one line of JSON.
func jsonLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// verifyBatch verifies every file and writes one result per file: a line
// of text, or with asJSON one JSON object per line. It returns exitInvalid
// if any file is invalid or cannot be read.
func verifyBatch(entries []entry, opts *c2paseal.VerifyOptions, asJSON bool, stdout, stderr io.Writer) int {
	code := exitValid
	counts := map[verify.State]int{}
	errs := 0
	for _, e := range entries {
		if e.err != nil {
			code, errs = exitInvalid, errs+1
			if asJSON {
				if err := jsonLine(stdout, map[string]string{"file": e.path, "error": e.err.Error()}); err != nil {
					fmt.Fprintln(stderr, "c2paseal:", err)
					return exitInvalid
				}
			} else {
				fmt.Fprintf(stdout, "%s: error: %v\n", e.path, e.err)
			}
			continue
		}
		r := c2paseal.VerifyFile(e.path, opts)
		state := r.State()
		counts[state]++
		if state == verify.Invalid {
			code = exitInvalid
		}
		if asJSON {
			if err := jsonLine(stdout, struct {
				File    string         `json:"file"`
				Results *verify.Result `json:"validation_results"`
				State   verify.State   `json:"validation_state"`
			}{e.path, r, state}); err != nil {
				fmt.Fprintln(stderr, "c2paseal:", err)
				return exitInvalid
			}
			continue
		}
		fmt.Fprintf(stdout, "%s: %s\n", e.path, state)
		for _, s := range r.Statuses() {
			if s.Kind() == verify.Failure {
				fmt.Fprintf(stdout, "  failure %s\n", s.Code)
			}
		}
	}
	if !asJSON {
		fmt.Fprintf(stdout, "%d files: %d Trusted, %d Valid, %d Invalid", len(entries),
			counts[verify.Trusted], counts[verify.Valid], counts[verify.Invalid])
		if errs > 0 {
			fmt.Fprintf(stdout, ", %d unreadable", errs)
		}
		fmt.Fprintln(stdout)
	}
	return code
}

// inspectBatch reads every file and writes one JSON object per line:
// {"file": ..., "manifest_store": {...}} or {"file": ..., "error": ...}.
// It returns exitInvalid if any file has no readable manifest store.
func inspectBatch(entries []entry, stdout, stderr io.Writer) int {
	code := exitValid
	for _, e := range entries {
		var line any
		err := e.err
		var s *c2paseal.ManifestStore
		if err == nil {
			s, err = c2paseal.Read(e.path)
		}
		if err != nil {
			code = exitInvalid
			line = map[string]string{"file": e.path, "error": err.Error()}
		} else {
			line = struct {
				File  string                  `json:"file"`
				Store *c2paseal.ManifestStore `json:"manifest_store"`
			}{e.path, s}
		}
		b, err := json.Marshal(line)
		if err != nil {
			code = exitInvalid
			b, _ = json.Marshal(map[string]string{"file": e.path, "error": err.Error()})
		}
		if _, err := fmt.Fprintln(stdout, string(b)); err != nil {
			fmt.Fprintln(stderr, "c2paseal:", err)
			return exitInvalid
		}
	}
	return code
}
