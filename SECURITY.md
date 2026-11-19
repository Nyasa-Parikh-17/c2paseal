# Security policy

C2paSeal parses untrusted files and signs on behalf of its users, so
security reports are welcome and taken seriously.

## Supported versions

| Version | Security fixes |
|---|---|
| Latest minor release (currently 0.7.x; 1.x after v1.0.0) | Yes |
| Older releases | No. Please upgrade |

Fixes ship as a patch release of the latest minor version. The fix is
listed in [CHANGELOG.md](CHANGELOG.md) and the GitHub release notes.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: on the repository's **Security** tab,
choose **Report a vulnerability** (GitHub private vulnerability reporting).
Please include:

- the affected version (`c2paseal version`) and component (library
  package, CLI, `sealsvc`, `sealstore`, web app, GitHub Action);
- what an attacker can do, and what they need (a crafted image, an API key,
  network access, ...);
- a minimal reproducer: for parser issues, the input file (or the fuzz
  corpus entry) and the call that misbehaves.

What to expect:

- an acknowledgement within 7 days;
- an assessment, and a plan for a fix, as soon as the problem is
  understood;
- credit in the release notes if you would like it, once the fix is
  released. Please give us a reasonable time to release a fix before you
  disclose the issue publicly.

## What counts

In scope:

- **Parsing untrusted input.** Any crash, panic, hang, or excessive memory
  or CPU use on a crafted JPEG, PNG, WebP, HEIC or AVIF file, manifest
  store, JUMBF, CBOR or COSE structure, time-stamp token or OCSP response.
  The library is designed so that bad input never panics; `Verify` turns
  malformed files into C2PA failure status codes.
- **Wrong verification results.** A file reported as Valid or Trusted when
  the C2PA 2.4 validation rules say it is not (a signature, hash binding,
  trust or time check that can be bypassed).
- **Signing.** Output that leaks key material, or a signed file whose
  manifest does not bind the bytes it claims to.
- **The services.** In `sealsvc` and `sealstore`: authentication or
  authorisation bypass, API keys or secrets in logs, request handling that
  can be used to exhaust the server.
- **The web app.** Anything that sends a user's file anywhere, or script
  injection through a crafted manifest.

Not vulnerabilities:

- **The TEST ONLY certificates and keys** in `testdata/pki` (and the web
  app's demo certificate) are public on purpose. Files signed with them
  prove nothing, and validators report them as untrusted.
- **What C2PA itself does not promise.** A valid signature shows who signed
  a file and that it has not changed since; it does not show that the
  picture is true. See "What C2PA does and does not prove" in the
  documentation.
- **The invisible watermark** is a public scheme with no key: anyone can
  read or remove it. It links copies to credentials and proves nothing by
  itself.
- **Unsupported formats.** Video, audio, PDF and other files are refused
  with an "unsupported file format" error. That is expected behaviour.

## How C2paSeal is hardened

- Every parser of untrusted input has a fuzz target, run nightly in CI;
  crashers are kept as regression tests.
- `govulncheck` checks every module in CI. Release binaries are built with
  the latest Go patch release, and the release notes name it.
- Builds use `CGO_ENABLED=0`: no C code, no memory-unsafe dependencies.
- The core module depends on three libraries plus the Go standard library
  (`fxamacker/cbor`, `veraison/go-cose`, `digitorus/timestamp`); a CI check
  keeps it that way.
- Results are checked against `c2patool`, the C2PA reference tool, on a
  corpus that includes deliberately broken and tampered files.
