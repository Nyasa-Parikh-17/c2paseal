package xmp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// c2patoolPacket is the packet c2patool 0.27.21 writes with --remote.
const c2patoolPacket = `<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 6.0.0">` +
	`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" ` +
	`xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:dc="http://purl.org/dc/elements/1.1/" ` +
	`xmlns:dcterms="http://purl.org/dc/terms/" xmpMM:DocumentID="xmp.did:cb9f5498" xmpMM:InstanceID="xmp.iid:cb9f5498" ` +
	`dcterms:provenance="http://127.0.0.1:8765/rside.c2pa"> </rdf:Description></rdf:RDF></x:xmpmeta>` + "\n" + `<?xpacket end="w"?>`

const rdfOpen = `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">`
const rdfClose = `</rdf:RDF></x:xmpmeta>`

func TestProvenance(t *testing.T) {
	for _, tc := range []struct {
		name, packet, want string
		ok                 bool
		err                error
	}{
		{"c2patool", c2patoolPacket, "http://127.0.0.1:8765/rside.c2pa", true, nil},
		{"element", rdfOpen + `<rdf:Description rdf:about="" xmlns:dcterms="http://purl.org/dc/terms/"><dcterms:provenance> https://a/b.c2pa </dcterms:provenance></rdf:Description>` + rdfClose, "https://a/b.c2pa", true, nil},
		{"other prefix", rdfOpen + `<rdf:Description xmlns:t="http://purl.org/dc/terms/" t:provenance="u"/>` + rdfClose, "u", true, nil},
		{"wrong namespace", rdfOpen + `<rdf:Description xmlns:dcterms="http://example.com/" dcterms:provenance="u"/>` + rdfClose, "", false, nil},
		{"escaped", rdfOpen + `<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" dcterms:provenance="a?x=1&amp;y=2"/>` + rdfClose, "a?x=1&y=2", true, nil},
		{"none", rdfOpen + `<rdf:Description rdf:about=""/>` + rdfClose, "", false, nil},
		{"twice", rdfOpen + `<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" dcterms:provenance="a"><dcterms:provenance>b</dcterms:provenance></rdf:Description>` + rdfClose, "", false, ErrAmbiguous},
		{"malformed", `<x:xmpmeta><rdf:RDF>`, "", false, ErrMalformed},
		{"not xml", "\x00\x01garbage<", "", false, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := Provenance([]byte(tc.packet))
			if got != tc.want || ok != tc.ok || !errors.Is(err, tc.err) {
				t.Errorf("got %q, %v, %v; want %q, %v, %v", got, ok, err, tc.want, tc.ok, tc.err)
			}
		})
	}
}

func TestSetProvenance(t *testing.T) {
	const url = `https://example.com/m.c2pa?a=1&b="2"`
	for _, tc := range []struct {
		name, packet string
		keep         []string // substrings that must survive
		err          error
	}{
		{"empty", "", nil, nil},
		{"replace c2patool attribute", c2patoolPacket, []string{`xmpMM:DocumentID="xmp.did:cb9f5498"`, "XMP Core 6.0.0"}, nil},
		{"add to description", rdfOpen + `<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Me</dc:creator></rdf:Description>` + rdfClose,
			[]string{"<dc:creator>Me</dc:creator>"}, nil},
		{"add to empty-element description", rdfOpen + `<rdf:Description rdf:about=""/>` + rdfClose, []string{`rdf:about=""`}, nil},
		{"namespace already declared", rdfOpen + `<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" dcterms:created="2020"/>` + rdfClose, []string{`dcterms:created="2020"`}, nil},
		{"prefix taken", rdfOpen + `<rdf:Description xmlns:dcterms="http://example.com/" dcterms:x="1"/>` + rdfClose, []string{`dcterms:x="1"`}, nil},
		{"replace element", rdfOpen + `<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/"><dcterms:provenance>old</dcterms:provenance></rdf:Description>` + rdfClose, nil, nil},
		{"no description", rdfOpen + rdfClose, nil, ErrNoDescription},
		{"malformed", "<a><b></a>", nil, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := SetProvenance([]byte(tc.packet), url)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err %v, want %v", err, tc.err)
			}
			if err != nil {
				return
			}
			got, ok, err := Provenance(out)
			if !ok || got != url || err != nil {
				t.Errorf("read back %q, %v, %v\n%s", got, ok, err, out)
			}
			for _, k := range tc.keep {
				if !bytes.Contains(out, []byte(k)) {
					t.Errorf("lost %q\n%s", k, out)
				}
			}
			// Setting it again is stable.
			again, err := SetProvenance(out, url)
			if err != nil || !bytes.Equal(again, out) {
				t.Errorf("second SetProvenance changed the packet (%v)", err)
			}
		})
	}
}

func TestNewPacket(t *testing.T) {
	p := NewPacket("https://x/y.c2pa")
	if !strings.HasPrefix(string(p), "<?xpacket begin=\"\xEF\xBB\xBF\"") {
		t.Errorf("packet does not start with an xpacket header carrying a BOM: %q", p[:30])
	}
	if v, ok, err := Provenance(p); v != "https://x/y.c2pa" || !ok || err != nil {
		t.Errorf("Provenance(NewPacket) = %q, %v, %v", v, ok, err)
	}
}

func FuzzProvenance(f *testing.F) {
	f.Add([]byte(c2patoolPacket))
	f.Add([]byte(rdfOpen + `<rdf:Description/>` + rdfClose))
	f.Add([]byte(rdfOpen + `<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/"><dcterms:provenance>x</dcterms:provenance></rdf:Description>` + rdfClose))
	f.Fuzz(func(t *testing.T, packet []byte) {
		v, ok, err := Provenance(packet)
		if err != nil {
			return
		}
		out, err := SetProvenance(packet, "https://example.com/new.c2pa")
		if err != nil {
			return // e.g. no rdf:Description
		}
		if got, ok2, err := Provenance(out); err != nil || !ok2 || got != "https://example.com/new.c2pa" {
			t.Fatalf("after SetProvenance: %q %v %v (before: %q %v)", got, ok2, err, v, ok)
		}
	})
}
