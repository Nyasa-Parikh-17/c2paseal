// Package cbormode holds the CBOR decode and encode modes shared by the
// manifest packages.
package cbormode

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var (
	// Dec decodes untrusted manifest CBOR. Duplicate map keys are rejected,
	// and maps decoded into `any` become map[string]any so they marshal to
	// JSON the way c2patool prints them.
	Dec cbor.DecMode

	// Enc is the write-path encoder: RFC 8949 core deterministic encoding.
	Enc cbor.EncMode
)

func init() {
	var err error
	Dec, err = cbor.DecOptions{
		DupMapKey:      cbor.DupMapKeyEnforcedAPF,
		DefaultMapType: reflect.TypeFor[map[string]any](),
	}.DecMode()
	if err != nil {
		panic(err) // static options; cannot fail at run time
	}
	Enc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
}
