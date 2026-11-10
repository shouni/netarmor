# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| v1.4.x | ✅ Supported |
| v1.3.x and earlier | ❌ Not supported |

## Reporting a Vulnerability

**Please do not report vulnerabilities in public issues.**

Report them privately through GitHub's [Private vulnerability reporting](https://github.com/shouni/netarmor/security/advisories/new).

Please include:

- The affected versions
- Steps to reproduce, or PoC code
- The expected impact (SSRF bypass, information disclosure, etc.)

Expect a first response within 7 days. If a fix is needed, it will be published as a GitHub Security Advisory after the patch is released.

## Threat Model

`securenet` aims to keep an application from reaching the internal network when it fetches a URL supplied from outside.

### In Scope

- **SSRF**: connections to private / loopback / link-local / CGNAT / reserved addresses, and to transition ranges that can embed IPv4 such as NAT64 / 6to4 / Teredo (see the README for the default block list)
- **DNS rebinding (TOCTOU)**: attacks that swap the DNS answer after the check and before the connection. `NewSafeHTTPClient` and `NewSafeTransport` prevent them by resolving the name right before connecting and **dialing the validated IP address directly**
- **Bypass via IPv4-mapped IPv6**: notation such as `::ffff:127.0.0.1` is normalized with `netip.Addr.Unmap()` before the check
- **Bypass via a proxy**: the `HTTP_PROXY` / `HTTPS_PROXY` environment variables are disabled by default
- **Downgrade via redirects**: the client returned by `NewSafeHTTPClient` refuses redirects from https to http by default

### Out of Scope

The following are not this package's responsibility and need to be handled by the caller.

- **Using `ValidateURL` on its own**: static validation alone cannot prevent DNS rebinding. Always use it together with `NewSafeHTTPClient` / `NewSafeTransport`
- **Redirects when `NewSafeTransport` is used on its own**: the redirect policy (`WithMaxRedirects` / `WithAllowRedirectDowngrade`) is a feature of `*http.Client.CheckRedirect` and is not part of the Transport. If you build your own `*http.Client`, these options are ignored and Go's default behavior applies (up to 10 redirects, with no downgrade restriction). IP validation lives in the Transport, so it stays in effect
- **The final destination when `WithProxy` is enabled**: the connection goes to the proxy server, so the final destination IP is not validated
- **When `WithAllowLoopback` / `WithAllowPrivate` / `WithAllowLinkLocal` are enabled**: the consequences of explicitly relaxing the policy are the caller's responsibility
- **Response body size and content**: decompression bombs and response content are not checked
- **Application-level authorization**: access control for public endpoints that are reachable

### Failing closed

When a hostname resolves to several IP addresses, the whole connection is refused if any one of them is restricted. Connecting only to the "safe" addresses is not done, because it can be bypassed whenever an attacker can influence resolution order.
