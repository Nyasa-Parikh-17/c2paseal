# Web app and WebAssembly

The [web app](https://nyasa-parikh-17.github.io/c2paseal/) is C2paSeal
compiled to WebAssembly. **Files never leave your browser:** it makes no
network requests with them. After the first visit it also works offline.

It has three tabs:

- **Verify:** drop an image to see who signed it, when, what was done to
  it, its history, and every status code. You can trust the demo root to
  see what "Trusted" looks like.
- **Sign a sample:** sign a picture with the TEST ONLY demo certificate,
  then download it.
- **Recover credentials:** read a [watermark](watermark.md) from a copy
  without credentials and fetch its manifest from a `sealstore` you name.
  This is the only feature that uses the network, and only to the store URL
  you give.

`c2paseal serve` runs the same app locally. Without the WebAssembly build,
it answers through a small HTTP API that returns the same JSON.

## Use the WebAssembly build in your page

```sh
cd cmd/c2paseal-wasm
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o c2paseal.wasm .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .
```

```js
const go = new Go(); // from wasm_exec.js
const { instance } = await WebAssembly.instantiateStreaming(fetch("c2paseal.wasm"), go.importObject);
go.run(instance);

const bytes = new Uint8Array(await file.arrayBuffer());
const result = JSON.parse(c2paseal.verify(bytes, { trustAnchors: pemText }));
console.log(result.validation_state); // "Invalid", "Valid" or "Trusted"
```

`globalThis.c2paseal` has:

| Function | Returns |
|---|---|
| `verify(bytes, opts)` | JSON as `c2paseal verify --json` |
| `sign(bytes, opts)` | The signed file and a summary, as `c2paseal sign --json` |
| `analyze(bytes, opts)` | Everything the web app displays: summary, signer, actions, history, statuses |
| `extractWatermark(rgba, width, height)` | The watermark ID and confidence from decoded pixels |
| `version()` | The build's version |

The options are documented in `go doc ./cmd/c2paseal-wasm`. The build is
about 3.9 MB gzipped. CI fails if it grows past 4 MiB.

## Limits in the browser

No time-stamping, no remote manifests and no online revocation checks:
they would need network access, and the page doesn't do that with your
files.
