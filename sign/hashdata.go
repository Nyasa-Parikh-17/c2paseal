package sign

import (
	"encoding/binary"

	"github.com/Nyasa-Parikh-17/c2paseal/container/bmff"
)

// hashDataLayout records where the values that are backfilled sit inside the
// encoded c2pa.hash.data CBOR.
type hashDataLayout struct {
	start, length, hash int // offsets of the 8-byte start, 8-byte length and 32-byte hash
}

// digestLen is the SHA-256 digest size.
const digestLen = 32

// encodeHashData encodes a c2pa.hash.data assertion with one exclusion:
//
//	{"exclusions": [{"start": u64, "length": u64}], "name": "jumbf manifest",
//	 "alg": "sha256", "hash": bstr(32), "pad": h''}
//
// The exclusion integers always use the 8-byte CBOR form (0x1B) so their
// encoded size does not depend on their value; that is what lets them be
// written in place after the manifest has been inserted. Field order follows
// c2pa-rs. Because of the fixed-width integers this encoding is valid CBOR
// but deliberately not core deterministic.
func encodeHashData(start, length uint64, hash []byte) ([]byte, hashDataLayout) {
	var b []byte
	text := func(s string) {
		b = appendHead(b, 3, uint64(len(s)))
		b = append(b, s...)
	}
	var l hashDataLayout

	b = appendHead(b, 5, 5) // map, 5 pairs
	text("exclusions")
	b = appendHead(b, 4, 1) // array of 1
	b = appendHead(b, 5, 2) // map, 2 pairs
	text("start")
	b = append(b, 0x1B) // uint, 8-byte argument
	l.start = len(b)
	b = binary.BigEndian.AppendUint64(b, start)
	text("length")
	b = append(b, 0x1B)
	l.length = len(b)
	b = binary.BigEndian.AppendUint64(b, length)
	text("name")
	text("jumbf manifest")
	text("alg")
	text("sha256")
	text("hash")
	b = appendHead(b, 2, digestLen)
	l.hash = len(b)
	h := make([]byte, digestLen)
	copy(h, hash)
	b = append(b, h...)
	text("pad")
	b = appendHead(b, 2, 0)
	return b, l
}

// encodeBMFFHash encodes a c2pa.hash.bmff.v3 assertion with c2pa-rs's
// default exclusions (the C2PA uuid box, ftyp, mfra, free, skip):
//
//	{"exclusions": [{"xpath": "/uuid", "data": [{"offset": 8, "value": bstr(16)}]},
//	  {"xpath": "/ftyp"}, {"xpath": "/mfra"}, {"xpath": "/free"}, {"xpath": "/skip"}],
//	 "alg": "sha256", "hash": bstr(32), "name": "jumbf manifest"}
//
// Field order follows c2pa-rs. Only the hash is backfilled; the exclusions
// name boxes, not offsets, so they are final from the start.
func encodeBMFFHash(hash []byte) ([]byte, hashDataLayout) {
	var b []byte
	text := func(s string) {
		b = appendHead(b, 3, uint64(len(s)))
		b = append(b, s...)
	}
	b = appendHead(b, 5, 4)
	text("exclusions")
	ex := bmff.DefaultExclusions()
	b = appendHead(b, 4, uint64(len(ex)))
	for _, e := range ex {
		pairs := uint64(1)
		if len(e.Data) > 0 {
			pairs++
		}
		b = appendHead(b, 5, pairs)
		text("xpath")
		text(e.XPath)
		if len(e.Data) > 0 {
			text("data")
			b = appendHead(b, 4, uint64(len(e.Data)))
			for _, d := range e.Data {
				b = appendHead(b, 5, 2)
				text("offset")
				b = appendHead(b, 0, d.Offset)
				text("value")
				b = appendHead(b, 2, uint64(len(d.Value)))
				b = append(b, d.Value...)
			}
		}
	}
	text("alg")
	text("sha256")
	text("hash")
	b = appendHead(b, 2, digestLen)
	l := hashDataLayout{start: -1, length: -1, hash: len(b)}
	h := make([]byte, digestLen)
	copy(h, hash)
	b = append(b, h...)
	text("name")
	text("jumbf manifest")
	return b, l
}

// encodeHashData encodes the manifest's c2pa.hash.data: with one exclusion
// for an embedded store, or with none for a store kept outside the file
// (a sidecar or remote store), where the hash covers the whole file.
func (m *Manifest) encodeHashData(start, length uint64, hash []byte) ([]byte, hashDataLayout) {
	if m.bmff {
		return encodeBMFFHash(hash)
	}
	if m.external {
		return encodeHashDataExternal(hash)
	}
	return encodeHashData(start, length, hash)
}

// encodeHashDataExternal encodes a c2pa.hash.data assertion without
// exclusions: {"name": "jumbf manifest", "alg": "sha256", "hash": bstr(32),
// "pad": empty bstr}. Only the hash is backfilled.
func encodeHashDataExternal(hash []byte) ([]byte, hashDataLayout) {
	var b []byte
	text := func(s string) {
		b = appendHead(b, 3, uint64(len(s)))
		b = append(b, s...)
	}
	b = appendHead(b, 5, 4)
	text("name")
	text("jumbf manifest")
	text("alg")
	text("sha256")
	text("hash")
	b = appendHead(b, 2, digestLen)
	l := hashDataLayout{start: -1, length: -1, hash: len(b)}
	h := make([]byte, digestLen)
	copy(h, hash)
	b = append(b, h...)
	text("pad")
	b = appendHead(b, 2, 0)
	return b, l
}

// appendHead appends a CBOR head with the shortest argument encoding.
func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= 0xFF:
		return append(b, m|24, byte(n))
	case n <= 0xFFFF:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= 0xFFFFFFFF:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), n)
}
