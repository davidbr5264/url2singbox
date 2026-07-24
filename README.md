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

- **Changed: `strict_route` now defaults OFF, not on.** After repeated
  reports of it breaking connectivity, a closer look turned up that this
  isn't one bug — it's a genuinely fragile setting in sing-box with several
  distinct, confirmed root causes depending on platform:
  - **Windows:** a confirmed bug ([SagerNet/sing-box#3515](https://github.com/SagerNet/sing-box/issues/3515))
    where `strict_route` breaks reaching `127.0.0.1`/localhost — relevant
    here specifically because this generator's own SOCKS/HTTP inbounds
    listen on `127.0.0.1`.
  - **Interface detection:** a confirmed bug
    ([SagerNet/sing-box#3440](https://github.com/SagerNet/sing-box/issues/3440))
    where `auto_detect_interface` can pick the wrong interface on more
    complex networks (multiple adapters, VPN-over-VPN), causing "no route
    to host" — independent of TUN config entirely.
  - **Routers/multi-interface Linux:** sing-box's own docs note
    `strict_route` needs manually added interface exclusions on complex
    topologies — it isn't fully automatic there.

  Given that spread — three distinct causes across three different
  platform categories, all reported against the same setting — this looks
  less like something a generated config can reliably work around and more
  like a setting worth trying deliberately rather than defaulting into. It
  still closes a real leak (see the Security notes above), so turn it on
  once your base setup is confirmed working, and go looking at the
  platform-specific issue above that matches your OS if it breaks
  connectivity again.
- **Fixed: TUN default MTU (9000) was a bad default, likely contributing to
  "laggy" TUN performance.** 9000 is a jumbo-frame size that only works if
  every hop on your real network path supports it end-to-end — most home,
  mobile, and corporate networks don't. A TUN interface set higher than
  what the actual path supports means packets need fragmenting, and if
  anything along the way blocks the ICMP messages fragmentation relies on,
  connections just hang until TCP times out and retries smaller — which
  looks exactly like intermittent stalling, not a hard failure. Default is
  now 1500 (standard Ethernet), with a hint suggesting 1400–1420 for
  mobile/PPPoE/nested-VPN paths.
- **Investigated: FakeIP crashing the core appears to match a confirmed
  sing-box bug, not a config issue.**
  [SagerNet/sing-box#2528](https://github.com/SagerNet/sing-box/issues/2528),
  "FakeIP (FakeIPTransport) still not started," shows the same crash
  signature: a nil-pointer panic inside `fakeip.(*Store).Create` when a
  query routes to FakeIP before its internal store has finished
  initializing — a startup race condition in the compiled binary, not
  something a JSON config can work around. Three previous config fixes
  in this generator (bootstrap resolver type, `detour` fields, rule
  ordering) addressed real, confirmed issues, but if the crash persists
  after all of them, this uninitialized-store race is the next suspect —
  check your sing-box core version and update to the latest stable, since
  this class of startup bug is typically what point releases fix. `sniff`
  + `hijack-dns` alone (FakeIP off) still give you full domain-based
  routing without touching the FakeIP code path at all, and is a solid
  fallback while confirming the core version.
- **Fixed: route rule order deviated from sing-box's own reference config.**
  `ip_is_private` had been moved to run before `hijack-dns` (see the
  now-corrected entry below), to protect LAN DNS resolution. That reasoning
  held up on its own, but sing-box's official reference client config for
  this exact combination — TUN + hijack-dns + FakeIP
  (https://sing-box.sagernet.org/manual/proxy/client/) — orders it
  `sniff → hijack-dns → ip_is_private`, not the other way around, and this
  generator hadn't been matching that. Given two real bugs already came from
  deviating from that same reference config in other ways, the rule order
  now matches it exactly again rather than relying on reasoning about
  interactions between FakeIP's address ranges and private-IP matching that
  can't be fully verified without a running instance to test against.
- **Fixed: core failing to start at all.** The previous fix added
  `"detour": "direct"` to the bootstrap DNS resolver and `"detour": "proxy"`
  to the remote one. Both were wrong:
  - `detour: "direct"` is a confirmed **fatal error** in sing-box —
    `start dns/https[local]: detour to an empty direct outbound makes no
    sense`. Omitting `detour` entirely already dials direct by default (per
    sing-box's own Dial Fields docs), so the explicit version is not just
    redundant but rejected outright.
  - `detour: "proxy"` also hit a confirmed sing-box compatibility bug:
    detouring a DoH server through a `urltest`-type outbound doesn't work
    reliably ([SagerNet/sing-box#3792](https://github.com/SagerNet/sing-box/issues/3792))
    — and `urltest` is this generator's default group type.

  Both are now removed entirely — no `detour` field on either DNS server.
  This is the same behavior the generator had before either was added, and
  it's what sing-box already defaults to safely. See "DNS server dials
  bypass the tunnel by design" below for the trade-off this brings back.
- **Fixed: FakeIP causing sing-box to crash-loop (and general sluggishness
  even before it hard-failed).** The bootstrap/`local` DNS resolver was
  using sing-box's special `"type": "local"` (OS-native resolution). This is
  a confirmed sing-box bug class — see
  [SagerNet/sing-box#2643](https://github.com/SagerNet/sing-box/issues/2643),
  "tun + hijack-dns + fakeip cause DNS resolve loopback": with TUN +
  hijack-dns + FakeIP together, that OS-native lookup can get re-captured by
  the tunnel and resolve to a *fake* IP, which sing-box then tries to dial
  as if it were the real proxy server — a loop with no way out. This matches
  both symptoms reported: the crash-restart cycle once it gave up entirely,
  and general slow-feeling page loads before that (queries silently stuck
  retrying through the loop even when something eventually got through).

  Fixed by matching sing-box's own reference client config
  (https://sing-box.sagernet.org/manual/proxy/client/) exactly:
  - The bootstrap resolver is now an explicit `"type": "udp"` server (reusing
    whichever provider you picked for Remote DNS, just over plain UDP),
    instead of the special `"local"` type. No more ambiguity about how the
    OS resolves it.
  - `dns.independent_cache: true` is now set whenever FakeIP is on, matching
    sing-box's own FakeIP client example — without it, a domain can get
    served the wrong kind of cached answer depending on which path resolved
    it first.
- **Fixed: TUN + strict_route causing "no internet" / pages hanging then
  suddenly loading.** The previous "port-53 block rule" used
  `"action": "reject"`, and for UDP — which is what almost all DNS uses —
  reject means *silently drop, no response*. Any query that sniffing didn't
  perfectly recognize as DNS in time got blackholed: the app/OS just hung
  until its own internal timeout, then fell back to something else (e.g. a
  browser's built-in DoH on port 443), which looked exactly like "stuck
  loading, then suddenly works." `strict_route` didn't cause this — it just
  stopped that traffic from leaking *around* the tunnel, which is what had
  been making it work by accident before.

  Two changes fix this properly:
  - The reject rule is **removed**. In its place, `hijack-dns` now also
    matches by `port: [53]` directly, not just sniffed protocol. This still
    guarantees nothing on port 53 bypasses the resolver you picked below —
    but by *redirecting* it to a real answer instead of dropping it, so it
    can never blackhole a query.
  - `ip_is_private` (your LAN) was briefly moved to run **before**
    `hijack-dns`, to stop DNS queries aimed at your own router from being
    hijacked too. That reasoning was sound on its own, but it deviated from
    sing-box's own reference client config for this combination, and has
    since been reverted — see the newer entry above.
- **Added: encrypted-only remote DNS, with a custom option.** The Remote DNS
  dropdown now also offers Quad9 DoH and a **Custom…** entry (hostname +
  DoH/DoT picker, defaulting to DoH). There's still no plaintext option in
  the list by design — a custom entry left blank falls back to Cloudflare
  DoH rather than silently doing nothing.
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
- **`strict_route` (TUN, off by default — see the changelog above for why)**
  stops packets addressed to the system's real gateway from slipping past
  the tunnel, closing a real leak. Turn it on once your base setup is
  confirmed working; it has confirmed platform-specific bugs that make it
  worth testing deliberately rather than defaulting into.

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
- **The bootstrap resolver is deliberately not sing-box's special `"local"`
  type.** An earlier version of this generator used it, on the assumption
  that sing-box's own outbound connections are always excluded from being
  recaptured by `auto_route`. That assumption was wrong for one specific,
  confirmed combination — TUN + hijack-dns + FakeIP together
  ([SagerNet/sing-box#2643](https://github.com/SagerNet/sing-box/issues/2643))
  — where that lookup could get pulled back into the tunnel and resolve to a
  fake address. The bootstrap resolver now uses an explicit plain `udp`
  server instead, matching sing-box's own reference client config, which
  sidesteps the ambiguity entirely rather than relying on that assumption
  holding in every combination of settings.
- **DNS server connections dial directly, bypassing the proxy — by design,
  not an oversight.** Neither DNS server entry (`remote` or the bootstrap
  `local`) sets a `detour`, and sing-box's own docs confirm that omitting it
  makes the dial equivalent to an explicit direct outbound. A `detour`
  pointing at your proxy group was tried and reverted twice: `"direct"` is a
  confirmed fatal error, and detouring a DoH server through a `urltest`
  group (this generator's default) hits a separate confirmed sing-box bug.
  The real consequence: your DoH/DoT queries to whichever resolver you pick
  leave from your real network path, not through the proxy server. The
  query *content* stays encrypted from your ISP either way, but the fact
  that you're making DoH queries to that resolver, from your real IP, is
  visible on your network. Domain-based routing for your actual browsing
  traffic (via sniff + hijack-dns) is unaffected by this — it's specifically
  the DNS server's own upstream connection that dials direct.

- **Port-53 hijack is deliberately broad, but safe.** It matches *any*
  traffic to port 53, not just recognizable DNS payloads — including
  non-standard traffic someone might be tunneling over port 53 to evade a
  firewall. Because the action is `hijack-dns` (redirect to a real answer)
  rather than a block, this can't blackhole traffic the way the earlier
  reject-based version did — but it will treat anything on port 53 as a DNS
  query and answer it as one, which will break a deliberate non-DNS use of
  that port. If you have one, put its target in "Bypass domains" or as a
  private-network exception so it's exempted before this rule runs.

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
