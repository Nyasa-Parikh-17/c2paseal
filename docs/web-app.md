# Web app and WebAssembly

The [C2paSeal website](https://nyasa-parikh-17.github.io/c2paseal/) has
three parts:

| Address | What it is |
|---|---|
| `/` | The home page |
| [`/app/`](https://nyasa-parikh-17.github.io/c2paseal/app/) | The app: drop an image to check it, or sign one |
| `/docs/` | This documentation |

The app is C2paSeal compiled to WebAssembly. **Files never leave your
browser:** it makes no network requests with them. After the first visit it
also works offline.

It has three tabs. You can link to each: `/app/`, `/app/#sign`,
`/app/#recover`.

- **Verify:** drop an image to see who signed it, when, what was done to
  it, its history, and every status code.
- **Sign:** sign the sample picture, or your own, with the TEST ONLY demo
  certificate, then download it.
- **Recover credentials:** read a [watermark](watermark.md) from a copy
  without credentials and fetch its manifest from a `sealstore` you name.
  This is the only feature that uses the network, and only to the store URL
  you give.

## Your trust list

A signer shows as **trusted** only if its certificate chains to a trust
anchor you choose. Without one, every real file shows "Signer not on your
trust list". This is correct, but not very useful.

Open **Your trust list** at the top of the app and load a PEM file of trust
anchors, such as the official C2PA trust list (see
[Certificates and trust](certificates.md)). The list:

- is used on every tab, together with the demo root if you tick its box;
- is kept in this browser (local storage) and offered again on your next
  visit, until you press **Remove**;
- is never uploaded. A list too large for the browser's storage is used for
  the current visit only.

The result line says which anchors were used, for example
`your trust list (C2PA-TRUST-LIST.pem)`.

## Run it locally

`c2paseal serve` serves the same website (home page and app) at
`http://127.0.0.1:8080/`. It has no WebAssembly build, so the app sends its
checks to that local process, which returns the same JSON. Your trust list
is sent along with each check. Recovering credentials needs the WebAssembly
build, so it is only on the published site.

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
| `analyze(bytes, opts)` | Everything the app displays: summary, signer, actions, history, statuses |
| `extractWatermark(rgba, width, height)` | The watermark ID and confidence from decoded pixels |
| `version()` | The build's version |

The options are documented in `go doc ./cmd/c2paseal-wasm`. The build is
about 3.9 MB gzipped. CI fails if it grows past 4 MiB.

## Limits in the browser

No time-stamping, no remote manifests and no online revocation checks:
they would need network access, and the page doesn't do that with your
files. Signing in the app uses the TEST ONLY demo certificate. For real
signing, use the [CLI](cli.md), the [library](library.md) or
[sealsvc](sealsvc.md).
