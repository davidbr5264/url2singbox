# Config Forge — vless:// → sing-box (Windows &amp; Linux)

A static, client-side tool that turns one or more `vless://` share links into
a `config.json` for the [sing-box](https://sing-box.sagernet.org) core.
Nothing is uploaded anywhere — parsing and config generation run entirely in
the browser tab.

Its DNS and routing generation is ported directly from v2rayN's actual C#
source (`SingboxDnsService.cs`, `SingboxRoutingService.cs`,
`SingboxOutboundService.cs`, `CoreConfigSingboxService.cs` — read from
[github.com/2dust/v2rayN](https://github.com/2dust/v2rayN)), not
reverse-engineered from example exports. An earlier version of this project
did exist as a separate, reverse-engineered generator; it's been removed in
favor of this one, since building against the real source is strictly more
trustworthy.

**UI**: a dark terminal/phosphor theme — near-black background, warm amber
accent, all-monospace (JetBrains Mono) throughout, bracketed `[ ]`-style
status indicators in place of icons. Each page shows a small "quick setup"
section up front and tucks everything else behind labeled, collapsible
"Advanced" sections (native `<details>`, no JS framework needed). TUN
interface name, MTU, and log level aren't fields at all — fixed to
`singbox_tun`, `9000`, and `warn`, since essentially nobody needs to change
them.

Two separate pages, one per platform — [`index.html`](index.html) for
Windows, [`linux.html`](linux.html) for Linux — cross-linked to each other.
Each page locks its platform via a hidden, single-option `<select>`; there's
no in-page toggle to get wrong. Both share the same `app.js` and `style.css`.

## What makes this different from a naive sing-box generator

Each verified directly against the real v2rayN source, not guessed:

- **3-tier bootstrap DNS**: a small plain-IP bootstrap resolver (not a hosts
  table) resolves the remote/direct DNS servers' own hostnames by default,
  so any custom DoH provider works — not just a hardcoded few. The static
  hosts table is still used automatically as a faster override, but only
  for providers it actually contains.
- **No forced TLS fingerprint**: if the link doesn't specify `fp=`, no
  `utls` block is added at all — v2rayN never fakes one you didn't ask for.
  An explicit "force fingerprint" option is available as this tool's own
  addition on top, clearly labeled as such.
- **Transport-aware SNI fallback**: derives the TLS SNI from the transport's
  own Host header (ws/httpupgrade) rather than a single flat query-param
  fallback.
- **Real TUN self-loop protection**: the TUN interface's own address is
  rejected-and-dropped, matched per single address rather than by CIDR
  prefix — on Linux, sing-tun registers a derived address in that same
  prefix range with systemd-resolved as a DNS upstream, so a prefix-wide
  match would silently break system DNS.
- **Automatic self-process exclusion**: this client's own traffic is always
  excluded from the tunnel by process name (platform-correct binary name),
  with no manual path to configure — matching v2rayN's own behavior.
- **ICMP routing policy** and **TLS record fragmentation** (anti-DPI SNI
  evasion) — real v2rayN TUN options.
- **DNS strategy** (`prefer_ipv4`/`prefer_ipv6`/`ipv4_only`/`ipv6_only`) is
  exposed and applied to `route.default_domain_resolver` and every DNS rule
  that routes to remote/direct — the same field a real, current v2rayN bug
  (GitHub issue #8863, Feb 2026) writes an Xray-style value into instead of
  a sing-box-style one; this tool uses the correct sing-box strings.
- Flow normalization (`xtls-rprx-vision-udp443` → `xtls-rprx-vision`),
  matching v2rayN's own normalization.

Not carried over from v2rayN's C# source: full protocol parity (VMess,
Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard — this tool is still
VLESS-only), FakeIP, raw custom-DNS passthrough, and the full
region-based geosite/geoip rule-splitting logic. This tool's own additions
on top (bypass domains, bypass applications, the geosite-private toggle,
settings persistence) are kept since they're independently useful, and
clearly distinguished in the UI from what v2rayN itself does.

## What it builds

- **TUN inbound** (`strict_route`, `gvisor` stack by default) + optional local
  SOCKS/HTTP mixed inbound (off by default — TUN-only unless you turn it on).
- **DNS over HTTPS** for remote resolution, tunneled through your own proxy
  outbound (`detour: proxy`). Local/direct resolution defaults to **System
  default** — v2rayN's actual default (119.29.29.29, DNSPod) is a
  China-anycast address unreachable for many users outside China, so this
  tool defaults to something that works everywhere instead, with DNSPod
  still available as an option.
- **Fail-closed routing**: `route.final` is your proxy outbound. Private IPs
  go direct via the built-in `ip_is_private` match — no file or download
  needed. The `geosite-private` rule-set (off by default) adds direct
  routing for known local-network *hostnames* on top of that.
- **VLESS parsing**: `security` (none/tls/reality), `flow`
  (xtls-rprx-vision), transports (`tcp`, `ws` incl. early-data, `grpc`,
  `http`, `httpupgrade`), ALPN, Reality `pbk`/`sid`. Multiple links generate
  a `selector` outbound so you can flip between servers.
- **Bypass domains**: a plain list of domains that should skip the proxy —
  applied to both DNS resolution and routing. One per line; a bare domain
  matches itself and its subdomains, a leading `.` matches subdomains only,
  and `keyword:`/`regex:` prefixes give substring/regex matching.
- **Bypass applications**: a list of executables (`steam.exe` on Windows,
  `steam` on Linux — or a full path, only the file name is used) whose
  traffic is sent direct via `process_name` matching, for apps that break
  under a VPN/TUN (games with anti-cheat, LAN-discovery tools, etc).
- **Settings persistence**: every option field auto-saves to your browser's
  `localStorage` and restores on your next visit. Windows and Linux pages
  share the same origin/storage, but the platform-shaped fields (rule-set
  path, bypass applications) are stored as fully separate profiles per
  page — visiting one page never shows, overwrites, or resets the other's
  stashed values. The pasted `vless://` link(s) are deliberately **not**
  persisted, since they carry UUIDs/keys and re-pasting one link is trivial
  compared to re-entering everything else. "Reset to defaults" only resets
  this page's own platform profile, not the other page's.

## Run it locally

No build step — it's plain HTML/CSS/JS.

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

## Deploy to Cloudflare Pages

**Option A — dashboard, no git required**
1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Upload assets**.
2. Drag in this folder's contents (`index.html`, `linux.html`, `style.css`,
   `app.js`, `_headers`).
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

## Extending

- `app.js` → `V2RAYN_DNS_PRESETS` / `V2RAYN_PREDEFINED_HOSTS` to add resolvers.
- `parseVlessLink()` to add transports (currently unhandled: `kcp`, `quic` as
  a VLESS transport — rare in the wild).
- `buildConfig()` is the single source of truth for the output shape; it's
  intentionally kept framework-free so it's easy to port to a CLI/Node script
  later if you want a non-browser version.
- Windows and Linux are separate pages sharing one `app.js`. Each page locks
  its platform via a hidden, single-option `<select id="optPlatform">` —
  `app.js` itself still supports live switching internally
  (`PLATFORM_DEFAULTS`, `ISOLATED_FIELDS`, `platformProfiles`,
  `switchPlatformProfile()`), left in place in case you want to reintroduce
  an in-page toggle later, but no current page exposes it in the UI. Adding
  a third platform means: a new `PLATFORM_DEFAULTS` entry, a
  `parseBypassApps()` validation branch, and a new HTML page cloned from one
  of the existing two with its defaults swapped. macOS would be the natural
  next one — process-name conventions are closer to Linux's (extension-less)
  than Windows's, and a plausible rule-set path would be
  `/usr/local/etc/sing-box/` or `/opt/homebrew/etc/sing-box/` depending on
  install method.

## Running on Linux

sing-box's TUN mode needs elevated privileges on Linux, same as on Windows:

- **Quick/manual runs**: `sudo sing-box run -c config.json`.
- **systemd service (recommended for anything long-running)**: grant
  capabilities instead of running fully as root —
  `CAP_NET_ADMIN` and `CAP_NET_RAW` for the TUN interface and routing, plus
  `CAP_SYS_PTRACE` if you're using the bypass-applications feature (process
  matching reads `/proc`). The official sing-box systemd service files
  already set these; see
  [sing-box's package-manager install docs](https://sing-box.sagernet.org/installation/package-manager/)
  if you're not using a packaged install.
- The default local rule-set path (`/etc/sing-box/geosite-private.srs`)
  matches where the official `.deb`/`.rpm` packages expect config files to
  live — adjust it if your install uses a different layout.

## Verify before trusting it

```powershell
sing-box.exe check -c config.json
```
