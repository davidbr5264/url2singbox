# sing-box Client Config Generator

A single static HTML file. Paste `vless://`, `vmess://`, `trojan://`, `ss://`,
`hysteria2://`/`hy2://`, or `tuic://` share links and get a ready client
config with a mixed SOCKS/HTTP proxy and/or TUN inbound. Everything runs
client-side in the browser; nothing is uploaded anywhere.

## Deploy to Cloudflare Pages

**Direct Upload:** Workers & Pages → Create → Pages → Upload assets → upload
this folder. No build command needed.

**Git integration:** connect the repo, leave the build command empty, set
output directory to `/`.

## What it generates

- **Inbounds:** a `mixed` proxy (SOCKS + HTTP on one port, loopback by
  default, optional auth) and/or TUN (configurable address, MTU, stack,
  `strict_route`).
- **Outbounds:** one per parsed proxy link, grouped under a `urltest`
  (auto-failover) or `selector` (manual) outbound, plus `direct`.
- **Routing:** `sniff` → `hijack-dns` (matching by port *or* sniffed
  protocol, combined via a `logical`/`or` rule) → private-IP bypass →
  bypass-domain list, matching sing-box's own reference client config
  (`sing-box.sagernet.org/manual/proxy/client/`). Unmatched traffic routes
  through the proxy group; if every proxy is unreachable, connections fail
  rather than silently going direct.
- **Device (Windows/macOS/Linux/Android/iOS)** changes several things that
  are genuinely platform-specific, not just labels:
  - **Self-exclusion** (the rule that stops sing-box's own traffic from
    looping back through its own tunnel) only applies on Windows/macOS/
    Linux, with the right process name per platform (`sing-box.exe` on
    Windows, `sing-box` — no extension — elsewhere). Skipped on Android/iOS,
    since those platforms exclude the VPN app's own traffic natively
    (Android's `VpnService.protect()`, the iOS NetworkExtension model) —
    the manual rule would be redundant there.
  - **`auto_redirect`** only appears as an option on Linux — confirmed
    Linux + nftables only in sing-box's own TUN docs; it does nothing on
    any other platform.
  - **Per-app routing** uses a different mechanism per platform, not just a
    different field name. Windows/macOS/Linux use a `process_name` route
    rule (an allowlist switches `route.final` to `direct`; a denylist
    leaves it on `proxy`). Android uses `include_package`/`exclude_package`
    directly on the TUN inbound — sing-box's native mechanism, mapping to
    Android's own `VpnService.addAllowedApplication`/
    `addDisallowedApplication`, which excludes apps at the OS level before
    packets reach sing-box's router at all, rather than matching and
    redirecting them after the fact. There's a confirmed open sing-box bug
    report (`SagerNet/sing-box#3387`) where this doesn't fully restrict
    traffic in some root/command-line Android setups — it's the correct,
    documented field, but not guaranteed airtight in every deployment, and
    the generator surfaces that as a warning when you use it. **iOS
    disables per-app routing entirely** — sing-box confirms process/package
    matching doesn't work there at all, a permanent limitation rather than
    something pending, so the control is disabled rather than silently
    generating a rule that won't do anything.
- **DNS:** an encrypted resolver (Cloudflare or Google DoH, or a custom IP)
  connected by its real hostname rather than a bare IP, resolved instantly
  via a static `hosts`-type DNS entry rather than a network round-trip —
  sidesteps any question of whether a provider's certificate covers a raw
  IP as a SAN. The same resolver bootstraps your proxy server's own
  hostname too, deliberately not using sing-box's special `"local"` DNS
  type, which has a confirmed loop bug combined with TUN + hijack-dns +
  FakeIP. FakeIP itself is optional; `sniff` + `hijack-dns` alone already
  give domain-based routing without it. HTTPS/SVCB DNS record queries
  (connection-upgrade hints some browsers send) get a short-circuited empty
  response rather than being resolved normally, which is safe and avoids
  them behaving unpredictably — particularly under FakeIP. Each DNS server
  gets its own independent cache (`independent_cache: true`, always on) —
  without it, an answer cached by one server can get wrongly reused when a
  different server should have answered a later query for the same domain,
  a confirmed sing-box bug class that isn't specific to FakeIP. Bypass
  domains resolve through a separate, plain-UDP, bare-IP resolver rather
  than the encrypted one — DNS-based CDN routing picks the nearest edge
  based on the resolver's location, not yours, so a domain you've
  explicitly bypassed (already decided doesn't need privacy protection)
  gets resolved geographically-accurately instead of through a foreign
  encrypted resolver that could land you on the wrong CDN edge.
- **Security:** certificate validation is enforced by default (any
  `insecure` flag a link tries to set gets stripped, with a visible warning
  either way), you'll get a warning if the mixed proxy is bound to a
  non-loopback address with no auth set, and there are optional DNS-level
  ad/tracker blocking and QUIC-blocking (forces TCP fallback, since QUIC —
  UDP:443 — is a second way traffic can misbehave under a tunnel, same
  category of issue as unencrypted DNS bypassing it) toggles.
- **TUN self-protection:** when TUN is on, the very first route rule —
  before `sniff`, before anything else — matches sing-box's own process
  name and routes it direct, unconditionally. This is defense-in-depth
  against a confirmed failure mode where `auto_detect_interface` (used to
  bind sing-box's own connections to the real network interface) fails to
  detect correctly on some networks/platforms, with no fallback of its own
  (`SagerNet/sing-box#1502`, `#3440`) — when that happens, sing-box's own
  traffic can get recaptured by its own tunnel instead of escaping it.

## Notes from a real-world config

Most of this generator's DNS and route structure now directly mirrors an
actual production config (v2rayN's Windows client default template) rather
than documentation alone: a single `mixed` inbound instead of separate
SOCKS/HTTP ones, `hosts`-type static DNS resolution for the encrypted
resolver's own hostname, a dedicated plain-UDP DNS tier for bypass domains
(matching its `direct_dns` pattern, for the CDN-locality reason explained
above), the combined port/protocol `hijack-dns` rule, the QUIC-blocking
option, the HTTPS/SVCB DNS short-circuit rule, always-on
`independent_cache`, `store_fakeip: false` when FakeIP is on, and the
process-name self-protection rule.

Two deliberate deviations remain, both privacy-motivated rather than
oversights:
- `default_domain_resolver` (bootstraps your proxy server's own hostname,
  if it's domain-based) stays on the *encrypted* resolver here, not the
  plain-UDP one the reference config uses for this. There's no reason to
  let even that one query go out in cleartext when keeping it encrypted
  costs nothing extra.
- That reference config uses `ip_accept_any` in a DNS rule to route general
  app queries to its `hosts` server. That's real, documented syntax
  (confirmed against sing-box's own `hosts` server docs) — but it solves a
  different problem than this generator needs: intercepting arbitrary app
  queries about domains in the hosts table. This generator's hosts table
  only exists to bootstrap its own DNS servers' connections, which
  `domain_resolver` (set directly on those server entries) already handles
  on its own, narrower and simpler.

## If something isn't working

**Fixed:** bypass domains and per-app routing entered in anything but the
exact bare form (a pasted URL like `https://example.com/path`, a domain with
a port, a full executable path) were silently producing rules that could
never match anything — not a routing bug, an input-parsing gap. Both fields
now clean their input properly (URLs → bare domain, paths → bare file name),
and the generator tells you what it actually used whenever that cleanup
changes something, so you can verify it did what you meant.

Set `"log": {"level": "debug"}` in the downloaded config and check your
sing-box client's log output. A real error line is worth far more than a
guess from documentation — most config-shaped problems become obvious once
you can see what sing-box itself is actually doing.

A couple of things worth knowing that aren't bugs in the config itself:

- **Browsers often do their own DNS-over-HTTPS**, independent of the OS —
  Chrome/Firefox/Edge frequently ship this on by default. When active, the
  browser's DNS never touches `hijack-dns` at all (it looks like ordinary
  HTTPS traffic), so it bypasses whatever resolver you configured here. Not
  a config bug — check your browser's own secure-DNS setting if domain
  routing looks like it's being ignored.
- **`strict_route`** closes a real leak — sing-box's own changelog (1.14.0-alpha.21)
  confirms it directly: on Windows, the platform-level DNS hijacking filter
  is only installed "when `strict_route` is enabled." Without it, DNS can go
  out any active network adapter rather than the tunnel. It also has its own
  confirmed platform quirks (e.g. reaching `127.0.0.1` on Windows). Defaults
  on; worth knowing which trade-off you're making if you turn it off.
- **FakeIP** has a confirmed sing-box crash bug in some versions
  (`SagerNet/sing-box#2528`, a startup race in the FakeIP store). If enabling
  it crashes your core, that's very likely a core-version issue rather than
  this config — check for an update, and leave it off in the meantime; it's
  optional.
- **uTLS fingerprinting (`fp=chrome` etc. in a link) isn't a strong
  anti-censorship measure**, per sing-box's own docs — this warning is
  reiterated across multiple release changelogs (1.12.17, 1.13.0-beta.6,
  1.13.0 itself), which is a sign SagerNet considers it worth repeating: it
  has "fundamental architectural limitations" against real detection, and
  NaiveProxy is recommended instead where TLS fingerprint resistance
  actually matters. This generator applies whatever fingerprint a link
  requests (or defaults to `chrome` for Reality) because that's what the
  link asked for — it isn't a claim that doing so provides strong protection.

## Protocol coverage

Each parser maps the common share-link query parameters (`security`, `sni`,
`fp`, `pbk`/`sid` for Reality, `type`/`path`/`host`/`serviceName` for
WS/gRPC/HTTP transports, `flow`, `obfs`, `alpn`, plugin options for
shadowsocks, port-hopping for Hysteria2) onto the matching sing-box outbound
fields. Share-link formats aren't fully standardized, so double-check
anything unusual against the official docs before relying on it:
https://sing-box.sagernet.org/configuration/
