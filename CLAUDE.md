# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What CERTOP is

A Go CLI that checks TLS certificate state across a fleet of servers: TCP reachability,
cert expiry and issuer, validation status, and which TLS versions each server accepts.
Runs one-shot (report for cron/monitoring) or as a `top`/`mtr`-style refreshing screen.

`SPEC.md` is the authoritative requirements document and records every design decision;
`README.md` is the user-facing manual. Both are in Spanish, as is all user-facing output —
match that. Keep `SPEC.md` in sync when the design changes.

## Commands

```sh
make            # default: cross-compile linux/amd64 + darwin/arm64 into dist/
make build      # native binary ./certop
make check      # go vet + go test ./...
make race       # go test -race ./...   (the UI test is the one that matters here)
make help       # list targets

go test ./internal/probe/ -run TestProbeNegotiatesLegacyVersions -v   # single test
```

Tests never touch the external network — they mint certs in-process with
`x509.CreateCertificate` and serve them from loopback listeners.

## Architecture

Flow: `cmd/certop` parses flags → `internal/inventory` loads targets → `internal/probe`
checks them concurrently → either `internal/report` (one-shot) or `internal/ui` (refresh).

- **`internal/probe`** is the core. `Checker.Check` dials TCP, handshakes with
  verification **off** so the leaf cert is always retrieved, then validates separately
  and reports the verdict as a `CertStatus`. `Checker.Run` fans out over a bounded worker
  pool and preserves input order, with an optional per-result callback for incremental UI
  updates.
- **`internal/ui`** owns a tcell screen directly. All shared state sits behind `App.mu`;
  `draw()` snapshots under the lock and only ever runs on the main loop goroutine, while
  check cycles run in their own goroutine and coalesce redraw requests through a
  buffered channel of size 1.

## Non-obvious constraints

These were found the hard way — don't undo them:

- **Legacy TLS probing.** `tlsConfig` explicitly offers every suite from
  `tls.CipherSuites()` *and* `tls.InsecureCipherSuites()`. Go's default client list omits
  RSA-kex and 3DES, and without them a server that only speaks TLS 1.0/1.1 gets
  misreported as refusing the version. Go 1.27 removed the `tls10server`, `tlsrsakex` and
  `tls3des` GODEBUGs — a `//go:debug` line naming any of them is now a **compile error** —
  but the suites are still implemented, so the explicit list is sufficient. The client can
  still negotiate TLS 1.0/1.1 whenever `MinVersion` is set explicitly.
- **Cert classification never switches on the error type.** With `Roots: nil`, macOS
  delegates to the platform verifier and returns different errors than Linux, so
  `classifyCert` decides self-signed vs. untrusted-chain by inspecting the certificate
  (`isSelfSigned`) instead of `errors.As`. Expiry is checked *before* chain validity,
  since an expired cert also fails verification and "EXPIRADO" is the useful label.
- **`isSelfSigned` uses `CheckSignature`, not `CheckSignatureFrom`** — the latter requires
  the signer to be a CA, which a self-signed *server* cert normally is not.
- **TOML map iteration is unordered**, so `inventory.Parse` sorts groups alphabetically to
  keep output stable across runs. Hosts keep file order within a group, and a host
  repeated on different ports is intentionally not deduplicated.
- **Version probing is cached** (~5 handshakes vs. 1). Bypassed by `--probe-always`,
  invalidated by the `p` key.

## Out of scope

STARTTLS (ports 25/587/143/5432). Every port in the spec's inventory is implicit TLS.
Raise it rather than silently adding it.
