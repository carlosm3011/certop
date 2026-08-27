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
resolves each target and checks every address concurrently → either `internal/report`
(one-shot) or `internal/ui` (refresh).

**One inventory entry is not one row.** `Checker.expand` resolves each host and emits one
unit per A and AAAA record, so row count varies with DNS. Rows are identified by
`Result.Key()` (group/host/port/ip), never by index.

- **`internal/probe`** is the core. `Checker.Check` dials TCP, handshakes with
  verification **off** so the leaf cert is always retrieved, then validates separately
  and reports the verdict as a `CertStatus`. `Checker.Run` fans out over a bounded worker
  pool and preserves input order, with an optional per-result callback for incremental UI
  updates.
- **`internal/ui`** owns a tcell screen directly. All shared state sits behind `App.mu`;
  `draw()` snapshots under the lock and only ever runs on the main loop goroutine, while
  check cycles run in their own goroutine and coalesce redraw requests through a
  buffered channel of size 1. `App.rows` is a map keyed by `Result.Key()`; each cycle
  stamps the rows it touches and prunes the untouched ones **only at cycle end**, so the
  screen never blanks mid-pass.

## Severity taxonomy

`probe.Result.Severity(warnDays)` is the single source of truth for how a row is judged,
and both the header counters and the row colours go through it. Keep new consumers on it
rather than re-deriving the rules:

- `SevProblem` — unreachable, no certificate, or `CertStatus != CertOK`.
- `SevWarning` — valid certificate expiring within `warnDays`.
- `SevOK` — everything else.

Note `report.ExitCode` does **not** use it yet: it triggers on unreachable/expiring only,
so a long-lived self-signed or mismatched cert still exits 0.

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
  invalidated by the `p` key. The cache key is `ip:port|verify-name`, not the hostname —
  two nodes behind one CNAME can differ, which is the whole point.
- **Resolved addresses are sorted** (v4 before v6, then by bytes). DNS rotates its answer
  order, and without sorting the rows would jump around on every refresh.
- **`expect` sets SNI *and* the verification name** (`Target.VerifyName()`), modelling what
  a client reaching the service through the CNAME actually does.
- **`ui.layout` allocates width strictly**: fixed columns first, then host, group, IP and
  issuer in that priority order, so the sum never exceeds the terminal width.

## Releases

No Go runner exists on the GitLab instance, so binaries are built **locally** by
`scripts/release.sh` (`make release`) and **committed to `release/`**; the pipeline
(`scripts/gitlab-release.sh`, shell runner, curl only) creates the Release object with
asset links pointing at the repo's raw files at that tag. **No token anywhere** — git goes
over ssh, CI uses `CI_JOB_TOKEN`.

- Order matters: the release commit must be pushed to `main` *before* the tag, since the
  asset URLs resolve files at the tag. Don't reorder those steps.
- `release/` is tracked; `dist/` stays gitignored so ordinary `make dist` doesn't dirty
  the tree. Roughly 1.7 MiB per release, measured.
- `make release` also rewrites `VERSION ?=` in the Makefile so the default follows the
  last release.
- `VERSION` accepts `1.1` or `v1.1`; the tag is always `v`-prefixed.
- `make release-dry` runs everything without touching, committing or pushing.
- The CI script uses `jq` when present to put the tag message in the release description,
  and falls back to a generated one otherwise — never hand-escape the tag message.
- The `+sha` in `--version` is the commit the binary was *built from*, necessarily one
  before the commit that contains it.

## Out of scope

STARTTLS (ports 25/587/143/5432). Every port in the spec's inventory is implicit TLS.
Raise it rather than silently adding it.
