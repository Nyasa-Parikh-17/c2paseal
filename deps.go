//go:build tools

package c2paseal

// Keeps the fixed dependency set from CLAUDE.md in go.mod until the
// packages that use them are written. Never compiled.
import (
	_ "github.com/digitorus/timestamp"
	_ "github.com/fxamacker/cbor/v2"
	_ "github.com/veraison/go-cose"
)
