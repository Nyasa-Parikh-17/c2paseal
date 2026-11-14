// Command interop runs every available C2PA validator over the test corpus
// and over files C2paSeal signs, and regenerates INTEROP.md: a file × tool
// matrix and a section per disagreement with its byte-level cause.
//
//	go run ./interop [-out INTEROP.md] [-work dir] [-require c2patool,c2pa-mcp,Credentio] [-strict]
//
// Tools: C2paSeal (in process), c2patool (the c2pa-rs reference CLI),
// c2pa-mcp (a pure-Go CLI over github.com/richardwooding/c2pa) and
// Credentio (Google's C++ library, its c2pa_validate tool). External tools
// are run as separate programs; a tool that is not installed is listed as
// not installed, never replaced by something else.
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
	require := flag.String("require", "", "comma-separated tools that must be installed (e.g. c2patool,c2pa-mcp,Credentio); fail otherwise")
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

	// Remote manifest stores: the c2patool fixtures' (testdata/remote/served)
	// and C2paSeal's own, on the address their files' XMP references.
	remote, err := startRemote(filepath.Join(td, "remote", "served"))
	if err != nil {
		return err
	}
	defer remote.Close()

	corpus, err := fixtureCorpus()
	if err != nil {
		return err
	}
	signed, err := signCorpus(td, work, corpus, remote)
	if err != nil {
		return err
	}
	corpus = append(corpus, signed...)

	tools := []tool{newC2paSeal(td), newC2patool(root, td), newC2paMCP(td), newCredentio(td)}
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
		row := row{Item: it, Facts: append(containerFacts(b), externalFacts(it.Path, b)...)}
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

// remoteAddr is where remote manifest stores are served while the harness
// runs. It is fixed: the c2patool fixtures in testdata/remote reference it.
const remoteAddr = "127.0.0.1:8765"

// remoteServer serves the fixture stores from disk and C2paSeal's remote
// stores from memory, under /c2paseal/.
type remoteServer struct {
	srv    *http.Server
	stores map[string][]byte
}

func startRemote(served string) (*remoteServer, error) {
	ln, err := net.Listen("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("remote manifest server: %w (is something else using %s?)", err, remoteAddr)
	}
	r := &remoteServer{stores: map[string][]byte{}}
	files := http.FileServer(http.Dir(served))
	r.srv = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if b, ok := r.stores[req.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/c2pa")
			w.Write(b)
			return
		}
		files.ServeHTTP(w, req)
	})}
	go r.srv.Serve(ln)
	return r, nil
}

// put registers a store (before any request for it) and returns its URL.
func (r *remoteServer) url(name string) string    { return "http://" + remoteAddr + "/c2paseal/" + name }
func (r *remoteServer) put(name string, b []byte) { r.stores["/c2paseal/"+name] = b }
func (r *remoteServer) Close() error              { return r.srv.Close() }

// signCorpus signs every unsigned fixture with the TEST ONLY PKI:
//
//   - c2paseal: plain; c2paseal+tsa: with a time-stamp from a local test TSA;
//   - c2paseal+parent: the c2paseal file signed again, so its manifest is
//     recorded as the parent ingredient (a chain of two manifests);
//   - c2paseal+sidecar: the store in <name>.c2pa next to the file;
//   - c2paseal+remote: the store only at the URL in the file's XMP.
func signCorpus(td, work string, corpus []item, remote *remoteServer) ([]item, error) {
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
		base := filepath.Base(it.Path)
		ext := filepath.Ext(base)
		var plain []byte
		for _, v := range []string{"c2paseal", "c2paseal+tsa", "c2paseal+parent", "c2paseal+sidecar", "c2paseal+remote"} {
			// The format is part of the name: small.jpg and small.png would
			// otherwise share one sidecar path (<stem>.c2pa).
			name := strings.TrimSuffix(base, ext) + "-" + strings.TrimPrefix(ext, ".") + "." + strings.ReplaceAll(v, "+", "-")
			opts := &sign.Options{Chain: chain, Signer: key}
			src := in
			switch v {
			case "c2paseal+tsa":
				opts.TSAURL = tsaURL
			case "c2paseal+parent":
				src = plain
			case "c2paseal+sidecar":
				opts.Sidecar = true
			case "c2paseal+remote":
				opts.Sidecar, opts.RemoteURL = true, remote.url(name+".c2pa")
			}
			s, err := c2paseal.SignAsset(src, opts)
			if err != nil {
				return nil, fmt.Errorf("sign %s (%s): %w", it.Name, v, err)
			}
			if v == "c2paseal" {
				plain = s.File
			}
			path := filepath.Join(work, name+ext)
			if err := os.WriteFile(path, s.File, 0o644); err != nil {
				return nil, err
			}
			switch v {
			case "c2paseal+sidecar":
				if err := os.WriteFile(c2paseal.SidecarPath(path), s.Store, 0o644); err != nil {
					return nil, err
				}
			case "c2paseal+remote":
				remote.put(name+".c2pa", s.Store)
			}
			out = append(out, item{Name: v + "/" + base, Path: path, Group: v, Format: asset.Detect(s.File)})
		}
	}
	return out, nil
}
