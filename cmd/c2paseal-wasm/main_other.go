//go:build !(js && wasm)

package main

import (
	"fmt"
	"os"
)

// main exists so the package builds (and its tests run) on every platform;
// the program itself is only useful as WebAssembly.
func main() {
	fmt.Fprintln(os.Stderr, "c2paseal-wasm: build with GOOS=js GOARCH=wasm; see the package documentation")
	os.Exit(2)
}
