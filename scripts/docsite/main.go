// Command docsite builds the documentation site from the Markdown files in
// docs/ (standard library only; the pages workflow publishes it at /docs/).
//
//	go run ./scripts/docsite -src docs -out _site/docs
//
// docs/nav.txt lists the pages in order; "## Name" lines start a group.
// Every .md file in docs/ must be listed, and every listed file must exist.
//
// It renders the Markdown subset the docs use: ATX headings, paragraphs,
// fenced code, nested lists, tables, block quotes, and inline code, bold,
// emphasis and links. Links to other pages become .html; links outside
// docs/ go to the file on GitHub. A link to a file that does not exist is
// an error, so broken links fail the build.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"html"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// repoURL is where links to files outside docs/ point.
const repoURL = "https://github.com/Nyasa-Parikh-17/c2paseal"

func main() {
	src := flag.String("src", "docs", "folder with the Markdown pages and nav.txt")
	out := flag.String("out", "_site/docs", "output folder")
	flag.Parse()
	if err := build(*src, *out); err != nil {
		fmt.Fprintln(os.Stderr, "docsite:", err)
		os.Exit(1)
	}
}

// page is one entry of the navigation.
type page struct {
	file  string // "quickstart.md"
	title string // its first heading
	group string
}

func build(src, out string) error {
	pages, err := readNav(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for i := range pages {
		b, err := os.ReadFile(filepath.Join(src, pages[i].file))
		if err != nil {
			return err
		}
		pages[i].title = firstHeading(string(b))
		if pages[i].title == "" {
			return fmt.Errorf("%s: no # heading", pages[i].file)
		}
	}
	for _, p := range pages {
		b, _ := os.ReadFile(filepath.Join(src, p.file))
		r := &renderer{src: src, file: p.file}
		body := r.render(string(b))
		if len(r.errs) > 0 {
			return fmt.Errorf("%s: %w", p.file, errors.Join(r.errs...))
		}
		doc := layout(pages, p, body)
		name := strings.TrimSuffix(p.file, ".md") + ".html"
		if err := os.WriteFile(filepath.Join(out, name), []byte(doc), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(out, "docs.css"), []byte(css), 0o644)
}

func readNav(src string) ([]page, error) {
	b, err := os.ReadFile(filepath.Join(src, "nav.txt"))
	if err != nil {
		return nil, err
	}
	var pages []page
	listed := map[string]bool{}
	group := ""
	for i, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "## "):
			group = strings.TrimSpace(l[3:])
		default:
			if listed[l] {
				return nil, fmt.Errorf("nav.txt:%d: %s listed twice", i+1, l)
			}
			if _, err := os.Stat(filepath.Join(src, l)); err != nil {
				return nil, fmt.Errorf("nav.txt:%d: %w", i+1, err)
			}
			listed[l] = true
			pages = append(pages, page{file: l, group: group})
		}
	}
	all, _ := filepath.Glob(filepath.Join(src, "*.md"))
	for _, f := range all {
		if !listed[filepath.Base(f)] {
			return nil, fmt.Errorf("%s is not in nav.txt", filepath.Base(f))
		}
	}
	if len(pages) == 0 || pages[0].file != "index.md" {
		return nil, errors.New("nav.txt must start with index.md")
	}
	return pages, nil
}

func firstHeading(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "# ") {
			return strings.TrimSpace(l[2:])
		}
	}
	return ""
}

// renderer turns one page's Markdown into HTML.
type renderer struct {
	src, file string
	errs      []error
	ids       map[string]int
}

var (
	listRe    = regexp.MustCompile(`^(\s*)([-*]|\d+\.)\s+(.*)$`)
	headingRe = regexp.MustCompile(`^(#{1,4})\s+(.*)$`)
	tableSep  = regexp.MustCompile(`^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$`)
)

func (r *renderer) render(md string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var b strings.Builder
	for i := 0; i < len(lines); {
		l := lines[i]
		t := strings.TrimSpace(l)
		switch {
		case t == "":
			i++
		case strings.HasPrefix(t, "<!--"):
			for i < len(lines) && !strings.Contains(lines[i], "-->") {
				i++
			}
			i++
		case strings.HasPrefix(t, "```"):
			lang := strings.TrimSpace(strings.TrimPrefix(t, "```"))
			i++
			var code []string
			for i < len(lines) && strings.TrimSpace(lines[i]) != "```" {
				code = append(code, lines[i])
				i++
			}
			if i == len(lines) {
				r.errs = append(r.errs, errors.New("unclosed code block"))
			}
			i++
			class := ""
			if lang != "" {
				class = ` class="language-` + html.EscapeString(lang) + `"`
			}
			fmt.Fprintf(&b, "<pre><code%s>%s</code></pre>\n", class, html.EscapeString(strings.Join(code, "\n")))
		case headingRe.MatchString(l):
			m := headingRe.FindStringSubmatch(l)
			level := len(m[1])
			id := r.id(m[2])
			if level == 1 {
				fmt.Fprintf(&b, "<h1 id=\"%s\">%s</h1>\n", id, r.inline(m[2]))
			} else {
				fmt.Fprintf(&b, "<h%d id=\"%s\">%s <a class=\"anchor\" href=\"#%s\" aria-label=\"Link to this section\">#</a></h%d>\n",
					level, id, r.inline(m[2]), id, level)
			}
			i++
		case strings.HasPrefix(t, "|") && i+1 < len(lines) && tableSep.MatchString(strings.TrimSpace(lines[i+1])):
			j := i + 2
			for j < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[j]), "|") {
				j++
			}
			b.WriteString(r.table(lines[i], lines[i+2:j]))
			i = j
		case strings.HasPrefix(t, ">"):
			var q []string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), ">") {
				q = append(q, strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(lines[i]), ">"), " "))
				i++
			}
			fmt.Fprintf(&b, "<blockquote>\n%s</blockquote>\n", r.render(strings.Join(q, "\n")))
		case listRe.MatchString(l):
			j := i + 1
			for j < len(lines) {
				lj := lines[j]
				if strings.TrimSpace(lj) == "" {
					// A blank line ends the list unless an indented line or
					// another item follows.
					if j+1 < len(lines) && (listRe.MatchString(lines[j+1]) || indent(lines[j+1]) >= 2) && strings.TrimSpace(lines[j+1]) != "" {
						j++
						continue
					}
					break
				}
				if !listRe.MatchString(lj) && indent(lj) == 0 {
					break
				}
				j++
			}
			b.WriteString(r.list(lines[i:j]))
			i = j
		default:
			var para []string
			for i < len(lines) {
				li := lines[i]
				ti := strings.TrimSpace(li)
				if ti == "" || strings.HasPrefix(ti, "```") || headingRe.MatchString(li) || listRe.MatchString(li) ||
					strings.HasPrefix(ti, ">") || (strings.HasPrefix(ti, "|") && len(para) == 0) {
					break
				}
				para = append(para, ti)
				i++
			}
			fmt.Fprintf(&b, "<p>%s</p>\n", r.inline(strings.Join(para, " ")))
		}
	}
	return b.String()
}

func indent(l string) int {
	return len(l) - len(strings.TrimLeft(l, " \t"))
}

func (r *renderer) id(text string) string {
	s := strings.ToLower(stripInline(text))
	var b strings.Builder
	dash := false
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteRune(c)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	id := strings.TrimSuffix(b.String(), "-")
	if id == "" {
		id = "section"
	}
	if r.ids == nil {
		r.ids = map[string]int{}
	}
	r.ids[id]++
	if n := r.ids[id]; n > 1 {
		id += "-" + strconv.Itoa(n)
	}
	return id
}

// stripInline removes Markdown inline markup, for heading ids.
func stripInline(s string) string {
	s = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`).ReplaceAllString(s, "$1")
	return strings.NewReplacer("`", "", "**", "", "*", "").Replace(s)
}

func splitRow(l string) []string {
	l = strings.TrimSpace(l)
	l = strings.TrimPrefix(l, "|")
	l = strings.TrimSuffix(l, "|")
	var cells []string
	var cur strings.Builder
	inCode := false
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c == '\\' && i+1 < len(l) && l[i+1] == '|':
			cur.WriteByte('|')
			i++
		case c == '`':
			inCode = !inCode
			cur.WriteByte(c)
		case c == '|' && !inCode:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

func (r *renderer) table(head string, rows []string) string {
	var b strings.Builder
	b.WriteString("<div class=\"table\"><table>\n<thead><tr>")
	for _, c := range splitRow(head) {
		fmt.Fprintf(&b, "<th>%s</th>", r.inline(c))
	}
	b.WriteString("</tr></thead>\n<tbody>\n")
	for _, row := range rows {
		b.WriteString("<tr>")
		for _, c := range splitRow(row) {
			fmt.Fprintf(&b, "<td>%s</td>", r.inline(c))
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody></table></div>\n")
	return b.String()
}

// item is one list item: its marker's indent, its text and its sub-lists'
// lines.
type item struct {
	text  []string
	child []string
}

func (r *renderer) list(lines []string) string {
	m := listRe.FindStringSubmatch(lines[0])
	base := len(m[1])
	ordered := m[2] != "-" && m[2] != "*"
	var items []*item
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if mm := listRe.FindStringSubmatch(l); mm != nil && len(mm[1]) <= base {
			items = append(items, &item{text: []string{mm[3]}})
			continue
		}
		it := items[len(items)-1]
		if listRe.MatchString(l) || len(it.child) > 0 {
			it.child = append(it.child, l)
		} else {
			it.text = append(it.text, strings.TrimSpace(l))
		}
	}
	tag := "ul"
	if ordered {
		tag = "ol"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<%s>\n", tag)
	for _, it := range items {
		fmt.Fprintf(&b, "<li>%s", r.inline(strings.Join(it.text, " ")))
		if len(it.child) > 0 {
			b.WriteString("\n" + r.list(it.child))
		}
		b.WriteString("</li>\n")
	}
	fmt.Fprintf(&b, "</%s>\n", tag)
	return b.String()
}

var linkRe = regexp.MustCompile(`^\[([^\]]+)\]\(([^)\s]+)\)`)

// inline renders inline markup: `code`, **bold**, *emphasis*, [links](url)
// and <https://autolinks>.
func (r *renderer) inline(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case rest[0] == '`':
			if j := strings.IndexByte(rest[1:], '`'); j >= 0 {
				b.WriteString("<code>" + html.EscapeString(rest[1:1+j]) + "</code>")
				i += j + 2
				continue
			}
		case strings.HasPrefix(rest, "**"):
			if j := strings.Index(rest[2:], "**"); j > 0 {
				b.WriteString("<strong>" + r.inline(rest[2:2+j]) + "</strong>")
				i += j + 4
				continue
			}
		case rest[0] == '*' && len(rest) > 1 && rest[1] != ' ':
			if j := strings.IndexByte(rest[1:], '*'); j > 0 && rest[j] != ' ' {
				b.WriteString("<em>" + r.inline(rest[1:1+j]) + "</em>")
				i += j + 2
				continue
			}
		case rest[0] == '[':
			if m := linkRe.FindStringSubmatch(rest); m != nil {
				fmt.Fprintf(&b, `<a href="%s">%s</a>`, html.EscapeString(r.link(m[2])), r.inline(m[1]))
				i += len(m[0])
				continue
			}
		case strings.HasPrefix(rest, "<http"):
			if j := strings.IndexByte(rest, '>'); j > 0 {
				u := rest[1:j]
				fmt.Fprintf(&b, `<a href="%s">%s</a>`, html.EscapeString(u), html.EscapeString(u))
				i += j + 1
				continue
			}
		}
		b.WriteString(html.EscapeString(rest[:1]))
		i++
	}
	return b.String()
}

// link rewrites a link target: pages in docs/ become .html; files outside
// docs/ point at GitHub. A relative target that does not exist is
// recorded as an error.
func (r *renderer) link(u string) string {
	if strings.Contains(u, "://") || strings.HasPrefix(u, "mailto:") || strings.HasPrefix(u, "#") {
		return u
	}
	target, frag, _ := strings.Cut(u, "#")
	if frag != "" {
		frag = "#" + frag
	}
	repoPath := path.Clean(path.Join("docs", target))
	if strings.HasPrefix(repoPath, "../") {
		r.errs = append(r.errs, fmt.Errorf("link %q leaves the repository", u))
		return u
	}
	st, err := os.Stat(filepath.Join(r.src, "..", filepath.FromSlash(repoPath)))
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("broken link %q", u))
		return u
	}
	if strings.HasPrefix(repoPath, "docs/") && path.Ext(repoPath) == ".md" && !strings.Contains(strings.TrimPrefix(repoPath, "docs/"), "/") {
		return strings.TrimSuffix(path.Base(repoPath), ".md") + ".html" + frag
	}
	kind := "blob"
	if st.IsDir() {
		kind = "tree"
	}
	return repoURL + "/" + kind + "/main/" + repoPath + frag
}

func layout(pages []page, cur page, body string) string {
	var nav strings.Builder
	group := ""
	open := false
	for _, p := range pages {
		if p.group != group {
			if open {
				nav.WriteString("</ul>\n")
			}
			group = p.group
			fmt.Fprintf(&nav, "<p class=\"group\">%s</p>\n<ul>\n", html.EscapeString(group))
			open = true
		} else if !open {
			nav.WriteString("<ul>\n")
			open = true
		}
		attr := ""
		if p.file == cur.file {
			attr = ` aria-current="page"`
		}
		fmt.Fprintf(&nav, "<li><a href=\"%s.html\"%s>%s</a></li>\n", strings.TrimSuffix(p.file, ".md"), attr, html.EscapeString(p.title))
	}
	if open {
		nav.WriteString("</ul>\n")
	}
	title := cur.title + " · C2paSeal docs"
	if cur.file == "index.md" {
		title = "C2paSeal docs"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<link rel="icon" href="../icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="docs.css">
</head>
<body>
<header class="top">
  <a class="brand" href="../"><img src="../icon.svg" alt="" width="22" height="22"> C2paSeal</a>
  <nav class="links" aria-label="Site"><a href="../app/">Check an image</a><a href="../app/#sign">Sign</a><a href="index.html" aria-current="page">Docs</a><a href="%s">GitHub</a></nav>
</header>
<div class="wrap">
<nav class="side" aria-label="Documentation">
%s</nav>
<main>
%s
<p class="edit"><a href="%s/blob/main/docs/%s">Edit this page on GitHub</a></p>
</main>
</div>
</body>
</html>
`, html.EscapeString(title), repoURL, nav.String(), body, repoURL, cur.file)
	return b.String()
}

const css = `:root {
  --bg: #fbfbf9; --panel: #ffffff; --text: #1c1c1a; --muted: #5d5d58; --border: #e2e2dc;
  --accent: #2f5bd3; --code-bg: #f1f1ed; --note-bg: #eef3ff;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #161615; --panel: #1d1d1b; --text: #ececea; --muted: #a5a59f; --border: #34342f;
    --accent: #8ab0ff; --code-bg: #262623; --note-bg: #1c2438;
  }
}
:root[data-theme="dark"] {
  --bg: #161615; --panel: #1d1d1b; --text: #ececea; --muted: #a5a59f; --border: #34342f;
  --accent: #8ab0ff; --code-bg: #262623; --note-bg: #1c2438;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--accent); }
/* The site's top bar: the same look as web/site/site.css and the app. */
.top { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 16px; padding: 12px 16px; border-bottom: 1px solid var(--border); background: var(--panel); }
.brand { display: inline-flex; align-items: center; gap: 8px; font-weight: 700; text-decoration: none; color: var(--text); font-size: 1.1rem; }
.links { display: flex; flex-wrap: wrap; gap: 4px 18px; }
.links a { text-decoration: none; }
.links a[aria-current="page"] { font-weight: 600; color: var(--text); }
.wrap { display: grid; grid-template-columns: 230px minmax(0, 1fr); gap: 40px; max-width: 1120px; margin: 0 auto; padding: 24px 16px 64px; }
.side { position: sticky; top: 16px; align-self: start; font-size: .94rem; }
.side ul { list-style: none; margin: 0 0 12px; padding: 0; }
.side li a { display: block; padding: 3px 8px; border-radius: 6px; text-decoration: none; color: var(--text); }
.side li a:hover { background: var(--code-bg); }
.side li a[aria-current="page"] { background: var(--note-bg); color: var(--accent); font-weight: 600; }
.side .group { margin: 16px 0 4px; padding: 0 8px; font-size: .78rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
main { min-width: 0; max-width: 780px; }
h1 { font-size: 2rem; line-height: 1.2; margin: 0 0 16px; }
h2 { font-size: 1.4rem; margin: 36px 0 12px; padding-top: 8px; border-top: 1px solid var(--border); }
h3 { font-size: 1.12rem; margin: 28px 0 8px; }
h4 { font-size: 1rem; margin: 20px 0 6px; }
.anchor { visibility: hidden; text-decoration: none; color: var(--muted); font-weight: 400; }
h2:hover .anchor, h3:hover .anchor, h4:hover .anchor { visibility: visible; }
p, ul, ol { margin: 0 0 14px; }
li { margin: 3px 0; }
li > ul, li > ol { margin: 4px 0; }
code { font: .88em/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--code-bg); padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; overflow-x: auto; margin: 0 0 16px; }
pre code { background: none; padding: 0; overflow-wrap: normal; font-size: .86rem; }
blockquote { margin: 0 0 16px; padding: 10px 14px; background: var(--note-bg); border-left: 3px solid var(--accent); border-radius: 0 8px 8px 0; }
blockquote p:last-child { margin: 0; }
.table { overflow-x: auto; margin: 0 0 16px; }
table { border-collapse: collapse; width: 100%; font-size: .94rem; }
th, td { text-align: left; vertical-align: top; padding: 7px 10px; border-bottom: 1px solid var(--border); }
th { background: var(--code-bg); }
.edit { margin-top: 48px; font-size: .9rem; color: var(--muted); }
@media (max-width: 820px) {
  .wrap { grid-template-columns: minmax(0, 1fr); gap: 8px; padding-top: 12px; }
  .side { position: static; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  .side ul { display: flex; flex-wrap: wrap; gap: 2px 4px; }
  .side .group { margin: 8px 0 2px; }
  h1 { font-size: 1.6rem; }
}
`
