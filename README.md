# Config Forge — vless:// → sing-box (Windows)

A static, client-side tool that turns one or more `vless://` share links into a
hardened `config.json` for the [sing-box](https://sing-box.sagernet.org) core
on Windows. Nothing is uploaded anywhere — parsing and config generation run
entirely in the browser tab.

## What it builds

- **TUN inbound** (`strict_route`, `gvisor` stack by default) + optional local
  SOCKS/HTTP mixed inbound.
- **DNS over HTTPS** for remote resolution, tunneled through your own proxy
  outbound (`detour: proxy`), with a `hosts`-type bootstrap so the resolver's
  own hostname never leaks over plaintext DNS. Local/direct resolution
  defaults to **System default** (your OS's own resolver) — this is what
  actually works reliably in practice, since it's ordinary sanctioned DNS
  traffic. A **Direct DoH** option is also available, with its own
  independent provider choice (Cloudflare/Google/Quad9/AliDNS/custom) —
  decoupled from the remote resolver, so if your network blocks direct
  connections to one provider you can pick a different one for this
  untunneled path without changing your remote resolver too. Direct DoH
  still depends on your network allowing *some* direct DoH provider through;
  on networks that block all of them, Direct DoH resolution for bypass
  domains will simply fail to load rather than fall back — sing-box has no
  built-in mechanism to automatically retry a failed DNS query against a
  different server, so System default remains the safer choice if you're
  unsure.
- **Fail-closed routing**: `route.final` is your proxy outbound. Only private
  IPs and the `geosite-private` rule-set go direct — everything else is
  tunneled or dropped, never silently sent out in the clear. `geosite-private`
  defaults to a local file at `C:\sing-box\geosite-private.srs`; switch the
  dropdown to auto-download if you'd rather not manage that file yourself.
- **Leak-path closers** (toggleable): reject UDP/443 (QUIC) so HTTP/3 can't
  route around a TCP-only path, and reject IPv6 since the TUN address here is
  IPv4-only.
- **VLESS parsing**: `security` (none/tls/reality), `flow` (xtls-rprx-vision),
  transports (`tcp`, `ws` incl. early-data, `grpc`, `http`, `httpupgrade`),
  uTLS fingerprint, ALPN, Reality `pbk`/`sid`. Multiple links generate a
  `selector` outbound so you can flip between servers.
- **Bypass domains**: a plain list of domains that should skip the proxy —
  applied to both DNS resolution and routing, evaluated before
  `geosite-private`. One per line; a bare domain matches itself and its
  subdomains, a leading `.` matches subdomains only, and `keyword:`/`regex:`
  prefixes give substring/regex matching.
- **Bypass applications**: a list of Windows executables (`steam.exe`, or a
  full path — only the file name is used) whose traffic is sent direct via
  `process_name` matching, for apps that break under a VPN/TUN (games with
  anti-cheat, LAN-discovery tools, etc). Applied to both DNS and routing,
  independent of the bypass-domain rule.

## Run it locally

No build step — it's plain HTML/CSS/JS.

```bash
cd vless2singbox
python3 -m http.server 8080
# open http://localhost:8080
```

## Deploy to Cloudflare Pages

**Option A — dashboard, no git required**
1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Upload assets**.
2. Drag in this folder's contents (`index.html`, `style.css`, `app.js`,
   `_headers`).
3. Deploy. You'll get a `*.pages.dev` URL immediately.

**Option B — git-connected (auto-deploys on push)**
1. Push this folder to a GitHub/GitLab repo.
2. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Connect to Git** → pick the repo.
3. Build settings: **Framework preset: None**, **Build command: (empty)**,
   **Build output directory: /**.
4. Deploy.

**Option C — Wrangler CLI**
```bash
npm install -g wrangler
wrangler pages deploy . --project-name=config-forge
```

The `_headers` file ships a Content-Security-Policy that blocks all outbound
`connect-src` — a safety net confirming the page can't phone home even by
accident, since it never needs to.

## sing-box compatibility notes

Checked against sing-box's official changelog and internals docs (current
stable: 1.13.x; 1.14 in beta) as of August 2026:

- The generated config uses the current unified `address` field for the TUN
  inbound, not the legacy split `inet4_address`/`inet6_address` fields
  (removed in 1.12.0) — no action needed.
- **`$schema` field — added, then reverted.** A previous version of this
  tool added it to the generated config on the assumption that an extra
  top-level field would be silently ignored. That was wrong: sing-box's
  config parser uses `DisallowUnknownFields()` (strict parsing), and
  `$schema` was only added as a recognized field in **1.14.0-beta.2** — on
  the 1.13.x stable branch most people run, it caused sing-box to reject the
  whole config and refuse to start. If you want editor autocomplete, point
  your editor's JSON schema settings at
  `https://sing-box.sagernet.org/schema.json` for the file instead of
  embedding it (e.g. VS Code's `json.schemas` setting) — that has no effect
  on what sing-box itself parses.
- **TUN IPv6 address — added, then reverted.** A previous version added a
  synthetic IPv6 address to the TUN interface whenever "Reject IPv6" was
  enabled (the default), reasoning that sing-box only routes address
  families actually present on the interface, so IPv6 needed to be present
  to be captured-and-rejected at all. The reasoning wasn't unfounded, but it
  came with an uncited, unverifiable claim about a specific v2rayN release
  doing the same thing — that claim has been removed, since it couldn't be
  confirmed. More importantly, the change itself caused real breakage: once
  the TUN captures IPv6, ordinary dual-stack sites that a browser tries over
  IPv6 first (common with Happy Eyeballs) get a hard reject instead of a
  clean timeout-and-fallback, which can break page loads outright rather
  than transparently falling back to IPv4. Reverted to IPv4-only TUN — IPv6
  simply isn't routed into the tunnel, so the reject rule is inert rather
  than actively enforced. Genuinely leak-proofing IPv6 requires disabling it
  at the OS/adapter level, which is outside what a config.json can do.
- **Outbound `domain_resolver` pin — added, then reverted.** A previous
  version explicitly set `domain_resolver` on the VLESS outbound. It was
  functionally redundant with `route.default_domain_resolver`, which already
  computes to the identical value in every config this tool can produce —
  removing it changes nothing, so it's gone for the sake of not carrying
  unexplained code.
- `dns.independent_cache: true` is kept deliberately even though it's
  deprecated as of 1.14.0-alpha.11. On 1.14+, the DNS cache always keys by
  transport regardless of this flag, but on the current 1.13.x stable branch
  it's still the explicit opt-in for that safer per-resolver cache isolation
  — removing it would silently weaken caching behavior for anyone not yet on
  1.14. It'll need to come out once 1.16.0 removes the field outright.
- sing-box 1.14 (alpha) is adding automatic TUN-level DNS hijacking
  (`dns_mode`/`dns_address`), which could eventually simplify the manual
  hijack-dns route rule here — not yet in a stable release, so no change made.

## Extending

- `app.js` → `DOH_PROVIDERS` to add resolvers.
- `parseVlessLink()` to add transports (currently unhandled: `kcp`, `quic` as
  a VLESS transport — rare in the wild).
- `buildConfig()` is the single source of truth for the output shape; it's
  intentionally kept framework-free so it's easy to port to a CLI/Node script
  later if you want a non-browser version.
- Currently Windows-only by design (Windows paths, `.exe` process-name hooks
  are not included since this tool builds a fresh config rather than a
  system-wide TUN passthrough list). A macOS/Linux variant would mainly need
  different `cache_file.path` conventions and no drive-letter paths for local
  rule-sets.

## Verify before trusting it

```powershell
sing-box.exe check -c config.json
```
