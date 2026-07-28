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
  a confirmed sing-box bug class that isn't specific to FakeIP.
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

A few things here came directly from analyzing an actual production config
(v2rayN's Windows client default template) rather than documentation alone:
a single `mixed` inbound instead of separate SOCKS/HTTP ones, `hosts`-type
static DNS resolution for the encrypted resolver's own hostname, the
combined port/protocol `hijack-dns` rule, the QUIC-blocking option, the
HTTPS/SVCB DNS short-circuit rule, always-on `independent_cache`, and the
process-name self-protection rule described above.

One thing from that config deliberately *not* copied as-is: it uses
`ip_accept_any` in a DNS rule to route general queries to its `hosts`
server. That's real, documented syntax (confirmed against sing-box's own
`hosts` server docs) — but it solves a different problem than what this
generator needs. It's for intercepting arbitrary app queries about domains
in the hosts table; this generator's hosts table only exists to bootstrap
its own DNS servers' connections, which `domain_resolver` (set directly on
those server entries) already handles on its own, narrower and simpler.

## If something isn't working

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
- **`strict_route`** closes a real leak — on Windows in particular, DNS can
  otherwise go out any active network adapter rather than the tunnel. It
  also has its own confirmed platform quirks in sing-box (e.g. reaching
  `127.0.0.1` on Windows). Defaults on; worth knowing which trade-off you're
  making if you turn it off.
- **FakeIP** has a confirmed sing-box crash bug in some versions
  (`SagerNet/sing-box#2528`, a startup race in the FakeIP store). If enabling
  it crashes your core, that's very likely a core-version issue rather than
  this config — check for an update, and leave it off in the meantime; it's
  optional.

## Protocol coverage

Each parser maps the common share-link query parameters (`security`, `sni`,
`fp`, `pbk`/`sid` for Reality, `type`/`path`/`host`/`serviceName` for
WS/gRPC/HTTP transports, `flow`, `obfs`, `alpn`, plugin options for
shadowsocks, port-hopping for Hysteria2) onto the matching sing-box outbound
fields. Share-link formats aren't fully standardized, so double-check
anything unusual against the official docs before relying on it:
https://sing-box.sagernet.org/configuration/
