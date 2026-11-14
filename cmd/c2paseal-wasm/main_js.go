//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	js.Global().Set("c2paseal", exports())
	select {} // keep the functions callable
}

// exports builds the globalThis.c2paseal object.
func exports() js.Value {
	api := js.Global().Get("Object").New()
	api.Set("verify", js.FuncOf(func(_ js.Value, args []js.Value) (out any) {
		defer recoverTo(&out)
		b, err := bytesArg(args, 0, "bytes")
		if err != nil {
			return string(errorJSON(err))
		}
		o := optsArg(args)
		vo := verifyOptions{TrustAnchors: str(o, "trustAnchors"), AllowedList: str(o, "allowedList"), TrustConfig: str(o, "trustConfig")}
		if vo.ManifestStore, err = optBytes(o, "manifestStore"); err != nil {
			return string(errorJSON(err))
		}
		return string(verifyJSON(b, vo))
	}))
	api.Set("sign", js.FuncOf(func(_ js.Value, args []js.Value) (out any) {
		defer recoverTo(&out)
		b, err := bytesArg(args, 0, "bytes")
		if err != nil {
			return string(errorJSON(err))
		}
		o := optsArg(args)
		so := signOptions{Cert: str(o, "cert"), Key: str(o, "key"), Title: str(o, "title"), SourceType: str(o, "sourceType"), NoHistory: o.Get("noHistory").Truthy()}
		if so.OCSPResponse, err = optBytes(o, "ocspResponse"); err != nil {
			return string(errorJSON(err))
		}
		return string(signJSON(b, so))
	}))
	api.Set("version", js.FuncOf(func(js.Value, []js.Value) any { return string(versionJSON()) }))
	return api
}

// recoverTo turns a panic into an error result. The library does not panic
// on bad input, but a panic here would stop the Go program and leave every
// later call failing, so it is reported instead.
func recoverTo(out *any) {
	if r := recover(); r != nil {
		*out = string(errorJSON(fmt.Errorf("internal error: %v", r)))
	}
}

var uint8Array = js.Global().Get("Uint8Array")

// bytesArg copies args[i], which must be a Uint8Array.
func bytesArg(args []js.Value, i int, name string) ([]byte, error) {
	if i >= len(args) || !args[i].InstanceOf(uint8Array) {
		return nil, fmt.Errorf("%s must be a Uint8Array", name)
	}
	return copyBytes(args[i]), nil
}

// optsArg returns args[1] if it is an object, else an empty object.
func optsArg(args []js.Value) js.Value {
	if len(args) > 1 && args[1].Type() == js.TypeObject {
		return args[1]
	}
	return js.Global().Get("Object").New()
}

// str returns o[name] if it is a string, else "".
func str(o js.Value, name string) string {
	if v := o.Get(name); v.Type() == js.TypeString {
		return v.String()
	}
	return ""
}

// optBytes returns o[name], which must be a Uint8Array if set.
func optBytes(o js.Value, name string) ([]byte, error) {
	v := o.Get(name)
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}
	if !v.InstanceOf(uint8Array) {
		return nil, fmt.Errorf("%s must be a Uint8Array", name)
	}
	return copyBytes(v), nil
}

func copyBytes(v js.Value) []byte {
	b := make([]byte, v.Length())
	js.CopyBytesToGo(b, v)
	return b
}
