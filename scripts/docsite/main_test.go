package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func render(t *testing.T, md string) (string, []error) {
	t.Helper()
	r := &renderer{src: filepath.Join("..", "..", "docs"), file: "test.md"}
	return r.render(md), r.errs
}

func TestRender(t *testing.T) {
	for _, tc := range []struct{ name, md, want string }{
		{"heading", "# Title\n\n## A `code` section", `<h1 id="title">Title</h1>
<h2 id="a-code-section">A <code>code</code> section <a class="anchor" href="#a-code-section" aria-label="Link to this section">#</a></h2>
`},
		{"paragraph", "one\ntwo **bold** *em* `a<b`", "<p>one two <strong>bold</strong> <em>em</em> <code>a&lt;b</code></p>\n"},
		{"code", "```sh\ngo run <x>\n```", "<pre><code class=\"language-sh\">go run &lt;x&gt;</code></pre>\n"},
		{"nested list", "- a\n  continued\n- b\n  - b1\n  - b2\n- c", "<ul>\n<li>a continued</li>\n<li>b\n<ul>\n<li>b1</li>\n<li>b2</li>\n</ul>\n</li>\n<li>c</li>\n</ul>\n"},
		{"ordered list", "1. one\n2. two", "<ol>\n<li>one</li>\n<li>two</li>\n</ol>\n"},
		{"table", "| A | B |\n|---|---|\n| `x\\|y` | [q](quickstart.md) |", `<div class="table"><table>
<thead><tr><th>A</th><th>B</th></tr></thead>
<tbody>
<tr><td><code>x|y</code></td><td><a href="quickstart.html">q</a></td></tr>
</tbody></table></div>
`},
		{"quote", "> **Note:** careful", "<blockquote>\n<p><strong>Note:</strong> careful</p>\n</blockquote>\n"},
		{"links", "[p](quickstart.md#install) [r](../README.md) [d](../watermark) [x](https://c2pa.org) <https://a.example/>",
			`<p><a href="quickstart.html#install">p</a> <a href="https://github.com/Nyasa-Parikh-17/c2paseal/blob/main/README.md">r</a> <a href="https://github.com/Nyasa-Parikh-17/c2paseal/tree/main/watermark">d</a> <a href="https://c2pa.org">x</a> <a href="https://a.example/">https://a.example/</a></p>
`},
		{"comment", "<!-- hidden -->\ntext", "<p>text</p>\n"},
	} {
		got, errs := render(t, tc.md)
		if len(errs) > 0 {
			t.Errorf("%s: errors %v", tc.name, errs)
		}
		if got != tc.want {
			t.Errorf("%s:\ngot  %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func TestBrokenLinks(t *testing.T) {
	for _, md := range []string{"[x](nope.md)", "[x](../../outside.md)", "```\nunclosed"} {
		if _, errs := render(t, md); len(errs) == 0 {
			t.Errorf("%q: no error", md)
		}
	}
}

// TestDocs builds the real docs folder: every page is in nav.txt and every
// link resolves.
func TestDocs(t *testing.T) {
	out := t.TempDir()
	if err := build(filepath.Join("..", "..", "docs"), out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"index.html", "quickstart.html", "what-c2pa-proves.html", "docs.css"} {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f, ".html") && !strings.Contains(string(b), `aria-current="page"`) {
			t.Errorf("%s: no current page in the navigation", f)
		}
	}
}

func TestNav(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.md"), []byte("# Home\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "extra.md"), []byte("# Extra\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "nav.txt"), []byte("index.md\n"), 0o644)
	if err := build(dir, t.TempDir()); err == nil || !strings.Contains(err.Error(), "extra.md is not in nav.txt") {
		t.Errorf("unlisted page: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "nav.txt"), []byte("index.md\nextra.md\nmissing.md\n"), 0o644)
	if err := build(dir, t.TempDir()); err == nil {
		t.Error("missing page: no error")
	}
}
