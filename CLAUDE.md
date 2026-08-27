# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`github.com/shouni/netarmor` is a zero-CLI Go library (no `main` package) with a single package, `securenet` — SSRF / DNS-rebinding defense for outbound calls. It has **no external dependencies**: `go.mod` carries no `require` and `go.sum` is empty. The `retry` package lived here until v1.4.0 and now belongs to `go-http-kit`; both of its consumers already depended on that module, and moving it is what emptied this go.mod.

**This library has a wide blast radius.** Sibling repos under `~/GolandProjects` list netarmor in 14 `go.mod` files, 7 of them as a *direct* dependency (`adk-review`, `ap-comp`, `ap-mv`, `ap-story`, `ap-voice`, `go-http-kit`, `go-web-reader`); the rest pull it in through `go-http-kit`, which re-exports netarmor behavior, so a change here can break repos that never import netarmor directly. Before removing or changing any exported symbol, grep the sibling repos for it — the v1.2.0 removal cycle needed coordinated edits in six repos.

## Commands

```bash
go build ./...
go vet ./...
go test -race ./...            # CI runs the race detector
test -z "$(gofmt -l .)"        # CI fails on unformatted files

# Single test / subtest (subtest names are Japanese; quote them)
go test ./securenet -run TestValidateURL
go test ./securenet -run 'TestNewSafeHTTPClient/BlockLoopbackConnection'

# Fuzzing (CI runs each for 60s)
go test ./securenet -run '^$' -fuzz FuzzValidateURL -fuzztime 30s
go test ./securenet -run '^$' -fuzz FuzzIsSecureServiceURL -fuzztime 30s

# Lint — must match the CI-pinned version (golangci-lint v2, config schema version "2")
golangci-lint run
```

CI (`.github/workflows/ci.yml`) also runs `govulncheck` and uploads a coverage profile. Go version comes from `go.mod` (currently 1.27 — `errors.AsType`, `slices`, and `net/netip` are all fair game).

## Architecture

### `securenet` — layered SSRF defense

Three files: `securenet.go` (public entry points + validation core), `options.go` (`Resolver`, `policy`, all `With*` options), `errors.go` (typed errors).

Two distinct layers that are meant to be used together; do not collapse them:

1. **Static validation** (`ValidateURL`) — parses the URL, allows `http`/`https` only after resolving the hostname and rejecting any restricted IP; every other scheme is `ErrDisallowedScheme` — `gs://` / `s3://` used to be waved through for cloud SDKs and no longer are. Takes no internal timeout; the caller's `ctx` governs.
2. **Connect-time validation** (`NewSafeHTTPClient` / `NewSafeTransport`) — the real TOCTOU defense. `options.dialContext` resolves the host itself, rejects if *any* returned IP is restricted, then dials the **already-resolved IP** rather than the hostname, so a rebinding DNS answer between check and connect cannot be exploited. Re-dialing by hostname would reintroduce the hole.

`IsSecureServiceURL` is a separate, weaker policy check (no DNS): HTTPS always OK, HTTP only for hostnames in `localdevHostnames`, empty host rejected. It answers "is this service URL configured sensibly", not "is it safe to fetch".

Key invariants to preserve:

- **`transport.Proxy` defaults to `nil`** so `HTTP_PROXY`/`HTTPS_PROXY` cannot route around the IP check. Only `WithProxy`/`WithProxyFromEnvironment` may set it. Note the trap documented on `WithProxy`: once a proxy is set, `DialContext` sees the *proxy's* address, so a private-IP proxy is itself blocked unless allowed via `WithAllowedCIDRs`.
- **`newTransport` nils out `DialTLSContext` / `DialTLS` / `Dial` after cloning the base transport.** `net/http` prefers `DialTLSContext` over `DialContext` for HTTPS, so a base transport carrying one would bypass IP validation entirely. `cloneBaseTransport` also type-asserts `http.DefaultTransport` with comma-ok — instrumentation libraries replace it globally, and a bare assertion panics.
- **The dial timeout bounds the whole `DialContext` call, not each address.** `net.Dialer.Timeout` applies per `DialContext` invocation, and the loop calls it once per resolved IP, so without the wrapping `context.WithTimeout` a 4-address host could take 4× the timeout. `NewSafeTransport` users have no `http.Client.Timeout` to catch that.
- **`policy.isRestricted` calls `Unmap()` first.** Without it, `::ffff:127.0.0.1` bypasses the IPv4 predicates. Evaluation order is allowlist → stdlib predicates → blocked prefixes; the allowlist wins over everything.
- **fail-closed on multi-address hosts**: one restricted IP rejects the whole connection. Never "pick the safe IP" — resolution order is attacker-influenced.
- **`defaultOptions` wraps the shared prefix slice in `slices.Clip`** so `WithBlockedCIDRs`' `append` can't mutate the package-level backing array.
- **IPv4-embedding transition ranges (NAT64 `64:ff9b::/96` + `64:ff9b:1::/48`, 6to4 `2002::/16` + `192.88.99.0/24`, Teredo `2001::/32`) are blocked wholesale**, not by extracting and checking the embedded IPv4 — extraction would interact badly with allowlist semantics and add parsing surface. NAT64 users opt in via `WithAllowedCIDRs` (documented on `defaultBlockedPrefixes`).

## Conventions

- **Doc comments and test subtest names are Japanese; error strings are English** (lowercase, no trailing punctuation, `package: detail` prefix), following Go convention for a published library. Don't reintroduce Japanese error text — consumers classify with `errors.Is`/`errors.As`, and tests must not assert on message substrings.
- The test package is **external** (`securenet_test`) — black-box only. If something needs internal access, prefer exposing it properly over switching the package.
- **`securenet` tests are hermetic**: every path that resolves a name injects `WithResolver(...)`. IP-literal hosts skip the resolver entirely (`resolveAndCheck` parses them directly), which is why the `httptest` cases work without one. Never add a test that hits real DNS.
- **No assertion library — plain `testing` only, and `go.mod` must stay empty.** netarmor is a base dependency in ~21 sibling `go.mod` files, and even a test-only requirement lands in every consumer's `go.sum` (verified: testify pulled `go.yaml.in/yaml/v3` in with it). An empty `go.sum` is itself the thing being protected — the same bar `go-utils` holds.
- Examples in `example_test.go` carry `// Output:` comments, so they run as tests. Keep them deterministic — inject a fixed resolver, never touch real DNS.
