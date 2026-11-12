// Package xmp reads and writes the one XMP property C2PA uses: the
// dcterms:provenance reference to a manifest store kept outside the asset
// (C2PA 2.4 §11.5, §15.5.3.1).
//
// It is not a general XMP toolkit. Provenance parses the packet with
// encoding/xml; SetProvenance edits the packet text in place, so everything
// else in it is kept byte for byte.
package xmp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Namespaces.
const (
	NSDCTerms = "http://purl.org/dc/terms/"
	NSRDF     = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
)

// Errors.
var (
	ErrMalformed     = errors.New("xmp: packet is not well-formed XML")
	ErrNoDescription = errors.New("xmp: packet has no rdf:Description")
	ErrAmbiguous     = errors.New("xmp: dcterms:provenance appears more than once")
)

// maxDepth bounds element nesting, so hostile packets cannot exhaust memory.
const maxDepth = 64

// Provenance returns the dcterms:provenance value of an XMP packet, as an
// attribute of rdf:Description or as an element. ok is false if the packet
// has none. A malformed packet gives ErrMalformed.
func Provenance(packet []byte) (value string, ok bool, err error) {
	loc, err := find(packet)
	if err != nil {
		return "", false, err
	}
	return loc.value, loc.found, nil
}

// location is what find learns about a packet.
type location struct {
	found bool
	value string

	// Attribute form: the raw start tag that carries the attribute.
	// Element form: the byte range of the element's text.
	attrTag    [2]int
	textRange  [2]int
	isElement  bool
	firstDesc  [2]int // raw start tag of the first rdf:Description, or -1
	descHasNS  bool   // that tag declares xmlns:dcterms already
	descPrefix string // "dcterms", or another prefix if that one is taken
}

func find(packet []byte) (*location, error) {
	loc := &location{firstDesc: [2]int{-1, -1}}
	d := xml.NewDecoder(bytes.NewReader(packet))
	d.Strict = true
	depth := 0
	inProv := false
	for {
		start := int(d.InputOffset())
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		end := int(d.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			if depth++; depth > maxDepth {
				return nil, fmt.Errorf("%w: nested too deeply", ErrMalformed)
			}
			if t.Name.Space == NSRDF && t.Name.Local == "Description" && loc.firstDesc[0] < 0 {
				loc.firstDesc = [2]int{start, end}
				loc.descPrefix = "dcterms"
				for _, a := range t.Attr {
					if a.Name.Space == "xmlns" && a.Name.Local == "dcterms" {
						if a.Value == NSDCTerms {
							loc.descHasNS = true
						} else {
							loc.descPrefix = "c2paDcterms"
						}
					}
				}
			}
			for _, a := range t.Attr {
				if a.Name.Space == NSDCTerms && a.Name.Local == "provenance" {
					if loc.found {
						return nil, ErrAmbiguous
					}
					loc.found, loc.value, loc.attrTag = true, a.Value, [2]int{start, end}
				}
			}
			if t.Name.Space == NSDCTerms && t.Name.Local == "provenance" {
				if loc.found {
					return nil, ErrAmbiguous
				}
				loc.found, loc.isElement, inProv = true, true, true
				loc.textRange = [2]int{end, end}
			}
		case xml.CharData:
			if inProv {
				loc.value += string(t)
				loc.textRange[1] = end
			}
		case xml.EndElement:
			depth--
			inProv = false
		default:
			if inProv {
				loc.textRange[1] = end
			}
		}
	}
	if loc.isElement {
		loc.value = strings.TrimSpace(loc.value)
	}
	return loc, nil
}

// SetProvenance returns a copy of packet with dcterms:provenance set to
// value. An existing value is replaced where it is; otherwise the property
// is added as an attribute of the first rdf:Description. A nil or empty
// packet gives a new, minimal packet.
func SetProvenance(packet []byte, value string) ([]byte, error) {
	if len(bytes.TrimSpace(packet)) == 0 {
		return NewPacket(value), nil
	}
	loc, err := find(packet)
	if err != nil {
		return nil, err
	}
	var out []byte
	switch {
	case loc.found && loc.isElement:
		r := loc.textRange
		out = splice(packet, r[0], r[1], escape(value))
	case loc.found:
		tag := packet[loc.attrTag[0]:loc.attrTag[1]]
		m := provAttr.FindAllSubmatchIndex(tag, -1)
		if len(m) != 1 {
			return nil, ErrAmbiguous
		}
		v := m[0][2:4] // the quoted value, quotes included
		out = splice(packet, loc.attrTag[0]+v[0], loc.attrTag[0]+v[1], `"`+escape(value)+`"`)
	case loc.firstDesc[0] >= 0:
		tag := packet[loc.firstDesc[0]:loc.firstDesc[1]]
		at := loc.firstDesc[1] - 1 // before '>'
		if bytes.HasSuffix(tag, []byte("/>")) {
			at--
		}
		add := ""
		if !loc.descHasNS {
			add += fmt.Sprintf(` xmlns:%s="%s"`, loc.descPrefix, NSDCTerms)
		}
		add += fmt.Sprintf(` %s:provenance="%s"`, loc.descPrefix, escape(value))
		out = splice(packet, at, at, add)
	default:
		return nil, ErrNoDescription
	}
	// The edit must leave a packet that reads back as value.
	if got, ok, err := Provenance(out); err != nil || !ok || got != value {
		return nil, fmt.Errorf("xmp: provenance did not read back after editing (%v)", err)
	}
	return out, nil
}

// provAttr matches a prefixed provenance attribute and its quoted value.
var provAttr = regexp.MustCompile(`\s[A-Za-z_][\w.\-]*:provenance\s*=\s*("[^"]*"|'[^']*')`)

func splice(b []byte, from, to int, s string) []byte {
	out := make([]byte, 0, len(b)-(to-from)+len(s))
	out = append(out, b[:from]...)
	out = append(out, s...)
	return append(out, b[to:]...)
}

// escape escapes s for XML text or a double-quoted attribute value
// (EscapeText also escapes quotes, as &#34; and &#39;).
func escape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s)) // a strings.Builder never fails
	return b.String()
}

// NewPacket returns a minimal XMP packet that holds only dcterms:provenance.
func NewPacket(value string) []byte {
	return []byte(`<?xpacket begin="` + "\xEF\xBB\xBF" + `" id="W5M0MpCehiHzreSzNTczkc9d"?>` +
		`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="` + NSRDF + `">` +
		`<rdf:Description rdf:about="" xmlns:dcterms="` + NSDCTerms + `" dcterms:provenance="` +
		escape(value) + `"/></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
}
