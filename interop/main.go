// Command interop runs every available C2PA validator over the test corpus
// and over files C2paSeal signs, and regenerates INTEROP.md: a file × tool
// matrix and a section per disagreement with its byte-level cause.
//
//	go run ./interop [-out INTEROP.md] [-work dir] [-require c2patool,c2pa-mcp] [-strict]
//
// Tools: C2paSeal (in process), c2patool (the c2pa-rs reference CLI) and
// c2pa-mcp (a pure-Go CLI over github.com/richardwooding/c2pa). External
// tools are run as separate programs; a tool that is not on PATH is listed
// as not installed, never replaced by something else.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/testtsa"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

// item is one file in the corpus.
type item struct {
	Name   string // display name, e.g. "signed/small.jpg" or "c2paseal/small.jpg"
	Path   string
	Group  string // fixture kind, or "c2paseal" / "c2paseal+tsa"
	Format string
}

func main() {
	out := flag.String("out", "", "report to write (default INTEROP.md in the repository root)")
	work := flag.String("work", "", "directory for C2paSeal-signed outputs (default a temporary directory)")
	require := flag.String("require", "", "comma-separated tools that must be installed (e.g. c2patool,c2pa-mcp); fail otherwise")
	strict := flag.Bool("strict", false, "exit 1 if any disagreement is unexplained")
	flag.Parse()
	if err := run(*out, *work, *require, *strict); err != nil {
		fmt.Fprintln(os.Stderr, "interop:", err)
		os.Exit(1)
	}
}

func run(out, work, require string, strict bool) error {
	td, err := fixtures.Dir()
	if err != nil {
		return err
	}
	root := filepath.Dir(td)
	if out == "" {
		out = filepath.Join(root, "INTEROP.md")
	}
	if work == "" {
		if work, err = os.MkdirTemp("", "c2paseal-interop-"); err != nil {
			return err
		}
		defer os.RemoveAll(work)
	}

	corpus, err := fixtureCorpus()
	if err != nil {
		return err
	}
	signed, err := signCorpus(td, work, corpus)
	if err != nil {
		return err
	}
	corpus = append(corpus, signed...)

	tools := []tool{newC2paSeal(td), newC2patool(root, td), newC2paMCP(td)}
	for _, name := range strings.Split(require, ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		found := false
		for _, t := range tools {
			if i := t.info(); i.Name == name {
				found = true
				if !i.Installed {
					return fmt.Errorf("required tool %s is not installed (not on PATH)", name)
				}
			}
		}
		if !found {
			return fmt.Errorf("unknown tool %q in -require", name)
		}
	}
	rep := &report{Generated: time.Now().UTC(), Root: root}
	for _, t := range tools {
		rep.Tools = append(rep.Tools, t.info())
	}
	for _, it := range corpus {
		b, err := os.ReadFile(it.Path)
		if err != nil {
			return err
		}
		row := row{Item: it, Facts: containerFacts(b)}
		for _, mode := range modes {
			for _, t := range tools {
				row.Results = append(row.Results, result{Tool: t.info().Name, Mode: mode, Outcome: t.run(it.Path, mode)})
			}
		}
		rep.Rows = append(rep.Rows, row)
		fmt.Fprintf(os.Stderr, "interop: %s\n", it.Name)
	}
	md := rep.markdown()
	if err := os.WriteFile(out, []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "interop: wrote %s (%d files, %d disagreements, %d unexplained)\n",
		out, len(rep.Rows), len(rep.disagreements()), rep.unexplained())
	if strict && rep.unexplained() > 0 {
		return fmt.Errorf("%d unexplained disagreement(s); see %s", rep.unexplained(), out)
	}
	return nil
}

// fixtureCorpus lists every JPEG and PNG fixture in testdata.
func fixtureCorpus() ([]item, error) {
	var out []item
	for _, k := range fixtures.Kinds {
		fs, err := fixtures.ListKind(k)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			out = append(out, item{Name: string(k) + "/" + f.Name, Path: f.Path, Group: string(k), Format: f.Format})
		}
	}
	return out, nil
}

// signCorpus signs every unsigned fixture with the TEST ONLY PKI, once
// without and once with a time-stamp from a local test TSA.
func signCorpus(td, work string, corpus []item) ([]item, error) {
	chain, key, err := c2paseal.LoadSigner(filepath.Join(td, "pki", "leaf-chain.pem"), filepath.Join(td, "pki", "leaf.key"))
	if err != nil {
		return nil, err
	}
	tsa, err := testtsa.New(filepath.Join(td, "pki"))
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: tsa, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()
	tsaURL := "http://" + ln.Addr().String()

	var out []item
	for _, it := range corpus {
		if it.Group != string(fixtures.Unsigned) {
			continue
		}
		in, err := os.ReadFile(it.Path)
		if err != nil {
			return nil, err
		}
		for _, v := range []struct{ group, tsa string }{{"c2paseal", ""}, {"c2paseal+tsa", tsaURL}} {
			b, err := c2paseal.SignBytes(in, &sign.Options{Chain: chain, Signer: key, TSAURL: v.tsa})
			if err != nil {
				return nil, fmt.Errorf("sign %s: %w", it.Name, err)
			}
			base := filepath.Base(it.Path)
			name := strings.TrimSuffix(base, filepath.Ext(base)) + "." + strings.ReplaceAll(v.group, "+", "-") + filepath.Ext(base)
			path := filepath.Join(work, name)
			if err := os.WriteFile(path, b, 0o644); err != nil {
				return nil, err
			}
			out = append(out, item{Name: v.group + "/" + base, Path: path, Group: v.group, Format: asset.Detect(b)})
		}
	}
	return out, nil
}
