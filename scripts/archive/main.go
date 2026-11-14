// Command archive packs a directory into a .tar.gz or .zip that depends only
// on the files' names and contents, so release archives are reproducible:
// entries are sorted, every timestamp is the given time, owners are 0, modes
// are 0755 for directories and executables and 0644 for everything else,
// and the gzip header carries no name or time.
//
// Usage: go run ./scripts/archive -mtime <unix seconds> [-exec name,...] <out.tar.gz|out.zip> <dir>
//
// The archive's top-level directory is the base name of <dir>. Files whose
// base name is listed in -exec are executable.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	mtime := flag.Int64("mtime", 0, "timestamp for every entry, in Unix seconds (for example $SOURCE_DATE_EPOCH)")
	execs := flag.String("exec", "", "comma-separated base names of executable files")
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: archive -mtime <unix seconds> [-exec name,...] <out.tar.gz|out.zip> <dir>")
		os.Exit(2)
	}
	for _, n := range strings.Split(*execs, ",") {
		if n != "" {
			executable[n] = true
		}
	}
	if err := run(flag.Arg(0), flag.Arg(1), time.Unix(*mtime, 0).UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "archive:", err)
		os.Exit(1)
	}
}

// executable holds the base names given with -exec.
var executable = map[string]bool{}

type entry struct {
	name string // slash-separated, prefixed with the top-level directory
	path string // on disk
	dir  bool
}

func run(out, dir string, mtime time.Time) error {
	entries, err := list(dir)
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	switch {
	case strings.HasSuffix(out, ".tar.gz"):
		err = writeTarGz(f, entries, mtime)
	case strings.HasSuffix(out, ".zip"):
		err = writeZip(f, entries, mtime)
	default:
		err = errors.New("output must end in .tar.gz or .zip")
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out)
	}
	return err
}

// list walks dir in lexical order (filepath.WalkDir's order).
func list(dir string) ([]entry, error) {
	top := filepath.Base(filepath.Clean(dir))
	var out []entry
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		name := top
		if rel != "." {
			name = path.Join(top, filepath.ToSlash(rel))
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("%s: not a regular file", p)
		}
		out = append(out, entry{name: name, path: p, dir: d.IsDir()})
		return nil
	})
	return out, err
}

func mode(e entry) fs.FileMode {
	if e.dir {
		return fs.ModeDir | 0o755
	}
	if executable[path.Base(e.name)] {
		return 0o755
	}
	return 0o644
}

func writeTarGz(w io.Writer, entries []entry, mtime time.Time) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	// gzip.Writer leaves Name empty and ModTime zero unless set.
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{
			Name:    e.name,
			Mode:    int64(mode(e).Perm()),
			ModTime: mtime,
			Format:  tar.FormatPAX,
		}
		var data []byte
		if e.dir {
			h.Typeflag = tar.TypeDir
			h.Name += "/"
		} else {
			h.Typeflag = tar.TypeReg
			if data, err = os.ReadFile(e.path); err != nil {
				return err
			}
			h.Size = int64(len(data))
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeZip(w io.Writer, entries []entry, mtime time.Time) error {
	zw := zip.NewWriter(w)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Modified: mtime, Method: zip.Deflate}
		h.SetMode(mode(e))
		if e.dir {
			h.Name += "/"
			h.Method = zip.Store
		}
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if e.dir {
			continue
		}
		data, err := os.ReadFile(e.path)
		if err != nil {
			return err
		}
		if _, err := fw.Write(data); err != nil {
			return err
		}
	}
	return zw.Close()
}
