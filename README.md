# sing-box Client Config Generator

A single static HTML file. Paste `vless://`, `vmess://`, `trojan://`, `ss://`,
`hysteria2://` / `hy2://`, or `tuic://` share links and it generates a ready
sing-box **client** config with a SOCKS inbound, a TUN inbound, or both.
All parsing happens in the browser — nothing is sent to a server.

## Deploy to Cloudflare Pages

**Option A — Direct Upload (fastest)**
1. Cloudflare dashboard → Workers & Pages → Create → Pages → Upload assets.
2. Upload this folder (just `index.html`).
3. Deploy. No build command, no framework, no output directory config needed.

**Option B — Git integration**
1. Push this folder to a GitHub/GitLab repo.
2. Pages → Connect to Git → select the repo.
3. Build command: *(leave empty)*. Build output directory: `/`.
4. Deploy.

## What it generates

- `inbounds`: `socks` and/or `tun`, per your toggles.
- `outbounds`: one entry per parsed link, plus a `urltest` (auto-failover) or
  `selector` (manual) group named `proxy`, plus `direct`.
- `route`: rule-action based sniffing (`{"action":"sniff"}`) and DNS hijack
  (`{"protocol":"dns","action":"hijack-dns"}`) — the current sing-box ≥1.13
  syntax, replacing the deprecated per-inbound `sniff` field and legacy `dns`
  outbound.
- `dns`: a remote resolver (Cloudflare/Google) for proxied domains, a `local`
  resolver, and optionally `fakeip` for smoother TUN routing.

## Changelog

- **Added (DNS security pass):**
  - An opt-in **"Block ads, malware & phishing (DNS)"** toggle. Uses
    SagerNet's own official `geosite-category-ads-all` rule-set (fetched
    from `raw.githubusercontent.com/SagerNet/sing-geosite` at runtime, not a
    third-party mirror) and rejects matching lookups at the DNS layer —
    before a connection is even attempted, not just after routing.
  - **Automatic IPv6 leak hardening.** If TUN is on but you leave the IPv6
    address blank, `dns.strategy` now switches to `ipv4_only` (instead of
    `prefer_ipv4`), suppressing AAAA answers so apps are less likely to
    try an IPv6 connection that would bypass the tunnel. A warning explains
    this is a mitigation, not a guarantee — full protection means disabling
    IPv6 in the OS too.
  - A warning when TUN is off (SOCKS/HTTP-only mode) explaining that DNS
    resolution then depends entirely on each app's own configuration, and
    that most apps will resolve domains locally in cleartext unless
    explicitly told to send DNS through the proxy.
- **Added:** a Security card (section 04) with two things:
  - **Enforce certificate validation** (on by default) — strips any
    `insecure`/skip-verify flag a link tries to set on its TLS block, since
    accepting an unverified certificate defeats TLS's entire purpose. The
    generator shows exactly which parsed proxy it stripped this from, or —
    if you turn enforcement off — which proxies are running with unverified
    certificates, so it's never silent either way.
  - A live warning if SOCKS/HTTP is bound to a non-loopback address with no
    username/password set — that combination is an open, unauthenticated
    proxy reachable by anyone who can hit that address.
- **Added:** HTTP proxy inbound (section 02, alongside SOCKS and TUN) — a
  third independent toggle using sing-box's `http` inbound type, with its
  own listen address/port and optional auth. Useful for tools that only
  read an `HTTP_PROXY`/`HTTPS_PROXY` env var rather than SOCKS.
- **Added (this pass, checked against sing-box 1.13.14 stable / 1.14.0-alpha docs):**
  `route.default_domain_resolver: "local"`. Every generated outbound has a
  domain name as its `server`, and this config always defines more than one
  DNS server — sing-box already effectively requires a resolver in that case,
  and 1.14.0 makes it a hard requirement (outbound DNS rule items are removed
  then). Just as important: without it, resolving the proxy's own hostname
  could get routed back out through "remote"/FakeIP — i.e. through the proxy
  outbound itself, before it has connected. Pointing it at the plain `local`
  resolver sidesteps that bootstrap deadlock entirely.
- **Added:** Hysteria2 port-hopping — `?mport=20000-20100,443` on a
  `hysteria2://` link now maps to the outbound's `server_ports` array.
- **Fixed:** VLESS outbounds were incorrectly setting `"network": "tcp"`
  whenever the link's transport was plain TCP or unspecified. That field is
  actually a tcp/udp *allow-list* on the outbound (unrelated to transport
  type) — setting it silently disabled UDP/QUIC. It's now left unset, so
  both stay enabled (the sing-box default).
- **Fixed:** shadowsocks SIP002 `?plugin=...` query params (e.g.
  `obfs-local;obfs=http;obfs-host=...`) were parsed and then discarded.
  They now map to the outbound's `plugin` / `plugin_opts` fields.
- **Added:** a bypass-domains input (section 03). One domain per line —
  each becomes a `domain_suffix` match (leading `.` or `*.` is stripped
  automatically, and the match already covers subdomains). Matching traffic
  gets both a `route` rule straight to `direct` and a `dns` rule pointing at
  the `local` resolver. The DNS rule is placed **before** the FakeIP
  catch-all rule — bypassed domains need a real IP, or dialing "direct"
  would try to reach a fake address that doesn't exist outside the tunnel.

## Security notes

A few things worth understanding rather than a toggle silently deciding for you:

- **Fail-closed by default.** `route.final` points at the proxy group, not
  `direct`. If every proxy in the group is unreachable, connections fail —
  they never silently fall back to going out unproxied. Don't add a rule
  that sends unmatched traffic to `direct` unless you specifically want that
  behavior; it removes this protection.
- **uTLS fingerprinting has real limits.** When a link specifies an `fp`
  (e.g. `fp=chrome`), the generator applies it as sing-box's uTLS
  fingerprint. This makes the TLS ClientHello *look* like a browser's, but
  sing-box's own docs note uTLS fingerprint spoofing has fundamental
  architectural limitations against sophisticated traffic analysis (JA3/JA4
  and similar) — it deters casual detection, not a determined observer. It's
  applied when a link asks for it, not invented as a false sense of security.
- **The DNS bootstrap step is a small, deliberate exception.** Every proxy
  outbound's own hostname resolves via the plain `local` DNS resolver
  (`route.default_domain_resolver`), not the encrypted `remote` one. This is
  intentional — resolving the proxy's own domain through the tunnel before
  the tunnel exists is a deadlock. The trade-off: your OS-configured
  resolver sees the proxy server's hostname (only that hostname, not your
  general browsing, which does go through `remote`/FakeIP). If the link's
  `server` is already a bare IP rather than a domain, this doesn't apply.
- **A blank IPv6 TUN address does not block IPv6.** It just means IPv6
  traffic isn't captured by the tunnel — the OS is free to route it out the
  real network interface, bypassing the proxy entirely. If you don't
  provide an IPv6 address, disable IPv6 at the OS level too, or you may leak
  IPv6 traffic (and IPv6 DNS/leaks) outside the tunnel while assuming
  everything is proxied.
- **`strict_route` (TUN, on by default)** stops packets addressed to the
  system's real gateway from slipping past the tunnel. Leave it on unless
  you have a specific reason not to.

## DNS security notes

- **EDNS Client Subnet is never sent.** Sing-box only adds an ECS record to
  outgoing DNS queries if `client_subnet` is explicitly set — this
  generator never sets it, so your approximate network location isn't
  leaked to whichever resolver (Cloudflare/Google) you pick.
- **DNS rebinding protection exists in sing-box, but isn't auto-generated
  here.** A malicious or compromised DNS server can resolve a public-looking
  domain to a private/internal address (e.g. `192.168.1.1`) to trick an app
  into reaching something on your LAN it shouldn't. sing-box 1.14+ supports
  detecting and rejecting this via an `evaluate` DNS rule paired with
  `match_response`, but the exact shape differs between the current stable
  (1.13) and 1.14, and getting it wrong silently breaks DNS resolution
  rather than failing loudly — so this is deliberately left as a manual,
  version-specific addition rather than something guessed here. See
  https://sing-box.sagernet.org/configuration/dns/rule_action/ if you want
  to add it by hand.
- **The `local` bootstrap resolver and TUN don't loop for normal desktop/
  mobile use** — sing-box's own outbound connections (including its
  bootstrap DNS lookups) are excluded from being recaptured by `auto_route`.
  This can differ if you're running sing-box as a shared *router/gateway*
  for other devices' traffic rather than your own device's client — that's
  a different deployment this generator doesn't target.

## Notes on protocol coverage

Each parser maps the common share-link query parameters (`security`, `sni`,
`fp`, `pbk`/`sid` for Reality, `type`/`path`/`host`/`serviceName` for
WS/gRPC/HTTP transports, `flow`, `obfs`, `alpn`, etc.) onto the matching
sing-box outbound fields. Exotic or vendor-specific query params some clients
add aren't all covered — open the generated JSON and adjust by hand if a
field looks off. Cross-check anything unusual against the official docs:
https://sing-box.sagernet.org/configuration/

## Minimum sing-box version

Generated configs target **sing-box 1.13+**. If you're on an older core,
see https://sing-box.sagernet.org/migration/ for the equivalent legacy
`inbound.sniff` / `dns`-outbound fields.
