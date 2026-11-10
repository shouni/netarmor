# 🛡️ Net Armor

[![CI](https://github.com/shouni/netarmor/actions/workflows/ci.yml/badge.svg)](https://github.com/shouni/netarmor/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)
[![Language](https://img.shields.io/badge/Language-Go-blue)](https://go.dev/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/netarmor)](https://go.dev/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/netarmor)](https://github.com/shouni/netarmor/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shouni/netarmor.svg)](https://pkg.go.dev/github.com/shouni/netarmor)

English | [日本語](README.ja.md)

## 🚀 About - validate the IP right before connecting, then dial the validated IP directly

**Net Armor** is a security library that protects a Go application's outbound traffic from SSRF (Server-Side Request Forgery) and DNS rebinding attacks. **It has no external dependencies** (the `require` block in `go.mod` is empty).

> **In v1.4.0 the `retry` package moved to [go-http-kit](https://github.com/shouni/go-http-kit).** Change your import path to `github.com/shouni/go-http-kit/retry`. The API is unchanged.

## ✨ Features

* **Strong defense (`securenet`)**: validates the IP address in the HTTP client's Transport layer right before connecting, and **connects directly to the validated IP**. This shuts out TOCTOU attacks such as DNS rebinding.
* **Typed errors**: every failure reason can be classified with `errors.Is` / `errors.As`. No need to compare error message strings.
* **Testability**: the resolver can be swapped, so unit tests can be written without depending on real DNS.
* **Zero dependencies**: runs on the standard library alone. Importing it does not widen your module graph.

---

## 📦 Package Structure

| Package | Description | Main API |
| --- | --- | --- |
| **`securenet`** | **Network security**. SSRF protection and sanity checks for service URLs. | `NewSafeHTTPClient` / `NewSafeTransport` / `ValidateURL` / `IsSecureServiceURL` |

---

## 🚦 Usage

### 1. Safe HTTP requests (`securenet`)

The default policy refuses connections to private / loopback / link-local and similar addresses, and ignores the `HTTP_PROXY` / `HTTPS_PROXY` environment variables.

```go
import (
    "time"
    "github.com/shouni/netarmor/securenet"
)

// Create a safe client that validates the IP right before connecting
client := securenet.NewSafeHTTPClient(10 * time.Second)

// Access a safe URL (e.g. a public API)
resp, err := client.Get("https://api.example.com/data")

// An unsafe URL (e.g. an attempt to reach the internal network) is blocked at the DialContext layer
_, err = client.Get("http://169.254.169.254/latest/meta-data/")
// errors.Is(err, securenet.ErrRestrictedIP) == true
```

To assemble your own `*http.Client`, you can take just the Transport.

```go
client := &http.Client{
    Transport: securenet.NewSafeTransport(10 * time.Second),
    Jar:       jar,
}
```

> ⚠️ **When you use only the Transport, the redirect policy does not apply** (IP validation lives in the Transport, so it stays in effect). See [Out of Scope in SECURITY.md](SECURITY.md#out-of-scope) for why and what it affects.

### 2. Static URL validation

To reject input early, at the point user input is accepted, use `ValidateURL`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

if err := securenet.ValidateURL(ctx, rawURL); err != nil {
    switch {
    case errors.Is(err, securenet.ErrRestrictedIP):
        // access to a restricted network
    case errors.Is(err, securenet.ErrDisallowedScheme):
        // disallowed scheme
    case errors.Is(err, securenet.ErrInvalidURL):
        // the URL failed to parse
    case errors.Is(err, securenet.ErrEmptyHost):
        // empty hostname
    case errors.Is(err, securenet.ErrNoAddresses):
        // name resolution returned nothing
    }
}
```

> ⚠️ **Static validation alone cannot prevent DNS rebinding.** The real defense against a DNS answer swapped after the check and before the connection lives in `NewSafeHTTPClient` / `NewSafeTransport`. Always use them together.

### 3. Tuning the policy

The default policy can be loosened or tightened with Options.

```go
// Connect to a local server in tests
client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithAllowLoopback())

// Allow only a specific range of the internal network
client := securenet.NewSafeHTTPClient(10*time.Second,
    securenet.WithAllowedCIDRs("10.1.0.0/16"))

// Go through a corporate proxy (the proxy's own address must be allowed too)
client := securenet.NewSafeHTTPClient(10*time.Second,
    securenet.WithProxyFromEnvironment(),
    securenet.WithAllowedCIDRs("10.0.0.0/8"))

// Swap the resolver to write tests that do not depend on real DNS
client := securenet.NewSafeHTTPClient(2*time.Second,
    securenet.WithResolver(myFakeResolver))
```

The `With...` options fall into six groups: swapping name resolution, explicitly enabling a proxy,
allowing and blocking specific networks, relaxing the policy, bringing your own Transport / Dialer,
and the redirect policy (see godoc for the full list and what each one does). **Allow rules take precedence over block rules.**

Redirect failures can be told apart by type as well. `errors.Is` / `errors.As` see through the `*url.Error` wrapper that `http.Client` returns.

```go
switch {
case errors.Is(err, securenet.ErrTooManyRedirects):  // the redirect limit was reached
case errors.Is(err, securenet.ErrRedirectDowngrade): // a downgrade from https to http
}
```

---

## 🛡️ Security Policy

By default the `securenet` package treats the following as "restricted networks" and blocks access to them.

* Private IP address ranges (RFC 1918, including IPv6 ULA)
* Loopback addresses (localhost, 127.0.0.1, ::1)
* Link-local addresses (169.254.0.0/16 and others)
* Unspecified addresses (0.0.0.0, ::) and "this network" (0.0.0.0/8)
* The carrier-grade NAT range (100.64.0.0/10)
* IETF protocol assignments (192.0.0.0/24) and Discard-Only (100::/64)
* The benchmarking network (198.18.0.0/15)
* Documentation / TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, 3fff::/20)
* Transition ranges that can embed IPv4 — NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16, 192.88.99.0/24), Teredo (2001::/32)
* Deprecated site-local (fec0::/10) and SRv6 SIDs (5f00::/16)
* Multicast and the reserved range (240.0.0.0/4)

IPv4-mapped IPv6 notation such as `::ffff:127.0.0.1` is normalized before the check, so the notation cannot be used to slip through. Transition ranges such as NAT64 can be a route to an internal IPv4 address embedded in the address (for example, `64:ff9b::a9fe:a9fe` is the metadata endpoint), so each range is blocked as a whole. If a NAT64 environment legitimately needs one, allow it explicitly with `WithAllowedCIDRs`.

When a hostname resolves to several IPs, **the whole connection is refused if any one of them is restricted** (fail-closed).

`IsSecureServiceURL` allows HTTPS URLs and HTTP URLs for local development, but rejects a URL with an empty hostname. It is a sanity check for configuration values and does no name resolution.

See [SECURITY.md](SECURITY.md) for the threat model in detail and how to report a vulnerability.

---

## 📜 License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
