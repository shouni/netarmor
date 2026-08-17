# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`github.com/shouni/netarmor` is a zero-CLI Go library (no `main` package) providing two independent packages for hardening outbound network calls: `securenet` (SSRF / DNS-rebinding defense) and `retry` (exponential backoff). Consumers import one or both; the packages have no dependency on each other.

**This library has a wide blast radius.** Sibling repos under `~/GolandProjects` list netarmor in ~21 `go.mod` files, 11 of them as a *direct* dependency (`ap-chain`, `ap-comic`, `ap-comp`, `ap-manga-web`, `ap-mcp`, `ap-music`, `ap-mv`, `go-gemini-client`, `go-http-kit`, `go-web-reader`, `git-gemini-web`). `go-http-kit` in particular re-exports netarmor behavior, so a change here can break repos that never import netarmor directly. Before removing or changing any exported symbol, grep the sibling repos for it — the v1.2.0 removal cycle needed coordinated edits in six repos.

## Commands

```bash
go build ./...
go vet ./...
go test -race ./...            # CI runs the race detector
test -z "$(gofmt -l .)"        # CI fails on unformatted files

# Single test / subtest (subtest names are Japanese; quote them)
go test ./securenet -run TestValidateURL
go test ./securenet -run 'TestNewSafeHTTPClient/BlockLoopbackConnection'
go test ./retry -run 'TestRun/成功'

# Fuzzing (CI runs each for 60s)
go test ./securenet -run '^$' -fuzz FuzzValidateURL -fuzztime 30s
go test ./securenet -run '^$' -fuzz FuzzIsSecureServiceURL -fuzztime 30s

# Lint — must match the CI-pinned version (golangci-lint v2, config schema version "2")
golangci-lint run
```

CI (`.github/workflows/ci.yml`) also runs `govulncheck` and uploads a coverage profile. Go version comes from `go.mod` (currently 1.26 — `errors.AsType`, `slices`, and `net/netip` are all fair game).

## Architecture

### `securenet` — layered SSRF defense

Three files: `securenet.go` (public entry points + validation core), `options.go` (`Resolver`, `policy`, all `With*` options), `errors.go` (typed errors).

Two distinct layers that are meant to be used together; do not collapse them:

1. **Static validation** (`ValidateURL`) — parses the URL, allows `gs://` and `s3://` unconditionally (cloud SDKs handle their own routing), allows `http`/`https` only after resolving the hostname and rejecting any restricted IP. Takes no internal timeout; the caller's `ctx` governs.
2. **Connect-time validation** (`NewSafeHTTPClient` / `NewSafeTransport`) — the real TOCTOU defense. `options.dialContext` resolves the host itself, rejects if *any* returned IP is restricted, then dials the **already-resolved IP** rather than the hostname, so a rebinding DNS answer between check and connect cannot be exploited. Re-dialing by hostname would reintroduce the hole.

`IsSecureServiceURL` is a separate, weaker policy check (no DNS): HTTPS always OK, HTTP only for hostnames in `localdevHostnames`, empty host rejected. It answers "is this service URL configured sensibly", not "is it safe to fetch".

Key invariants to preserve:

- **`transport.Proxy` defaults to `nil`** so `HTTP_PROXY`/`HTTPS_PROXY` cannot route around the IP check. Only `WithProxy`/`WithProxyFromEnvironment` may set it. Note the trap documented on `WithProxy`: once a proxy is set, `DialContext` sees the *proxy's* address, so a private-IP proxy is itself blocked unless allowed via `WithAllowedCIDRs`.
- **`policy.isRestricted` calls `Unmap()` first.** Without it, `::ffff:127.0.0.1` bypasses the IPv4 predicates. Evaluation order is allowlist → stdlib predicates → blocked prefixes; the allowlist wins over everything.
- **fail-closed on multi-address hosts**: one restricted IP rejects the whole connection. Never "pick the safe IP" — resolution order is attacker-influenced.
- **`defaultOptions` wraps the shared prefix slice in `slices.Clip`** so `WithBlockedCIDRs`' `append` can't mutate the package-level backing array.
- **IPv4-embedding transition ranges (NAT64 `64:ff9b::/96` + `64:ff9b:1::/48`, 6to4 `2002::/16` + `192.88.99.0/24`, Teredo `2001::/32`) are blocked wholesale**, not by extracting and checking the embedded IPv4 — extraction would interact badly with allowlist semantics and add parsing surface. NAT64 users opt in via `WithAllowedCIDRs` (documented on `defaultBlockedPrefixes`).

### `retry` — backoff wrapper

Three files: `retry.go` (`Run`/`RunValue`), `options.go` (`settings`, all `With*` options, defaults), `errors.go` (`*Error` + sentinels).

Built on `cenkalti/backoff/v5`, whose API differs from v4 in ways that matter here:

- `backoff.WithMaxTries(n)` counts **total attempts**, not retries — hence `addSaturating(s.maxRetries, 1)`.
- `MaxElapsedTime` defaults to 15 minutes upstream, so `WithMaxElapsedTime(s.maxElapsedTime)` is always passed (default 0 = disabled). Retries are bounded by count and context only.
- On context cancellation `backoff.Retry` returns `context.Cause(ctx)` and **discards the operation's last error**. `RunValue` therefore tracks `lastErr` in the closure and stores both in `*Error`. Removing that closure state silently loses the failure cause.

`Run` delegates to `RunValue[struct{}]` — keep the logic in one place.

Retry-After support: an operation error whose chain implements `DelayHinter` (`RetryAfter() time.Duration`, detected with `errors.As`) overrides the next backoff interval. The closure joins the op error with `*backoff.RetryAfterError` via `errors.Join`; backoff then uses that duration and resets its schedule. Because the joined error is an internal representation, the notify adapter passes `lastErr` (the original op error) to the hook, and `*Error.Err` stays the original too. `ShouldRetryFunc` returning false takes precedence over any hint.

`*Error` implements multi-error `Unwrap() []error`, so `errors.Is` matches the operation error, the context cause, *and* exactly one of `ErrPermanent` / `ErrExhausted`. The `Permanent` flag drives that classification; it's set in the closure when `shouldRetry` returns false.

## Conventions

- **Doc comments and test subtest names are Japanese; error strings are English** (lowercase, no trailing punctuation, `package: detail` prefix), following Go convention for a published library. Don't reintroduce Japanese error text — consumers classify with `errors.Is`/`errors.As`, and tests must not assert on message substrings.
- Both test packages are **external** (`securenet_test`, `retry_test`) — black-box only. If something needs internal access, prefer exposing it properly over switching the package.
- **`securenet` tests are hermetic**: every path that resolves a name injects `WithResolver(...)`. IP-literal hosts skip the resolver entirely (`resolveAndCheck` parses them directly), which is why the `httptest` cases work without one. Never add a test that hits real DNS.
- `retry` tests use millisecond intervals and `WithRandomizationFactor(0)` for determinism — never wait on the default 5s/30s intervals.
- Testify (`assert`/`require`) is used in `securenet`; `retry` uses plain `testing`.
- Examples in `example_test.go` carry `// Output:` comments, so they run as tests. Keep them deterministic (fixed resolver, zero jitter).
