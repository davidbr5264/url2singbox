/* ============================================================
   Config Forge — vless:// -> sing-box client config (Windows)
   Pure client-side. No network calls, no data leaves the tab.
   ============================================================ */

// ---------- predefined hosts table ----------
// Byte-for-byte from v2rayN's Global.PredefinedHosts — used as a fast-path
// override for the bootstrap/remote/direct DNS servers' own hostnames (see
// the DNS section of buildConfig for how the override is applied).
const V2RAYN_PREDEFINED_HOSTS = {
  "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
  "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
  "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
  "1dot1dot1dot1.cloudflare-dns.com": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
  "cloudflare-dns.com": ["104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
  "dns.cloudflare.com": ["162.159.61.8", "172.64.41.8", "2a06:98c1:52::8", "2803:f800:53::8"],
  "dot.pub": ["1.12.12.12", "120.53.53.53"],
  "doh.pub": ["1.12.12.12", "120.53.53.53"],
  "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
  "dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"],
  "dns.sb": ["45.11.45.11", "185.222.222.222", "2a09::", "2a11::"],
  "dns.umbrella.com": ["208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"],
  "dns.sse.cisco.com": ["208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"],
  "engage.cloudflareclient.com": ["162.159.192.1", "2606:4700:d0::a29f:c001"]
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Fixed rather than user-editable — nobody meaningfully needs to change
// these, so they're no longer fields in the UI at all.
const FIXED_TUN_NAME = "singbox_tun";
const FIXED_TUN_MTU = 9000;
const FIXED_LOG_LEVEL = "warn";

// ============================================================
// v2rayN-FAITHFUL DNS ADDRESS PARSING
// Direct port of ParseDnsAddress() in v2rayN's SingboxDnsService.cs.
// A single address string (no separate "mode" selector) is enough:
// "local"/"localhost" -> type local; a bare IP/host -> type udp;
// a URL with a scheme (https://, tls://, quic://, h3://) -> that type,
// with a "+local" suffix stripped. This mirrors v2rayN's own UX, where
// bootstrap/direct/remote DNS are each just one free-typed address field.
// ============================================================
function parseDnsAddress(address) {
  if (!address) return null;
  const first = address.split(address.includes(",") ? "," : ";")[0].trim();
  if (!first) return null;

  if (first === "local" || first === "localhost") {
    return { type: "local" };
  }

  let m = first.match(/^([a-z][a-z0-9+.-]*):\/\/(.+)$/i);
  let scheme = "", rest = first;
  if (m) { scheme = m[1].toLowerCase(); rest = m[2]; }

  if (scheme === "dhcp") {
    const server = { type: "dhcp" };
    if (rest && rest !== "auto") server.server = rest;
    return server;
  }

  // split host[:port][/path]
  let hostPort = rest, path = "";
  const slash = rest.indexOf("/");
  if (slash !== -1) { hostPort = rest.slice(0, slash); path = rest.slice(slash); }
  let host = hostPort, port = 0;
  const colon = hostPort.lastIndexOf(":");
  if (colon !== -1 && /^\d+$/.test(hostPort.slice(colon + 1))) {
    host = hostPort.slice(0, colon);
    port = parseInt(hostPort.slice(colon + 1), 10);
  }

  const server = {};
  server.type = scheme ? scheme.replace(/\+local$/i, "").toLowerCase() : "udp";
  server.server = host;
  if (port) server.server_port = port;
  if ((server.type === "https" || server.type === "h3") && path && path !== "/") {
    server.path = path;
  }
  return server;
}

// v2rayN's actual Global.Domain*DNSAddress default lists (first entry of
// each is what v2rayN itself defaults to) — DNSPod for direct/bootstrap
// reflects v2rayN's China-oriented defaults; "System default" below is
// this tool's own addition for networks where that's unreachable.
const V2RAYN_DNS_PRESETS = {
  bootstrap: ["119.29.29.29", "223.5.5.5", "localhost"],
  direct: ["119.29.29.29", "223.5.5.5", "https://doh.pub/dns-query", "https://dns.alidns.com/dns-query", "localhost"],
  remote: ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query", "https://dns.cloudflare.com/dns-query", "1.1.1.1", "8.8.8.8"]
};

// Path/process-name conventions differ by OS; the sing-box config.json
// schema itself does not. These two fields are the ones whose *content*
// is shaped for one platform and meaningless (or actively wrong) on the
// other, so each platform gets its own fully isolated copy — switching
// platforms swaps between two separate profiles rather than leaving stale
// Windows-shaped content sitting there while Linux is selected, or vice
// versa. (Self-process exclusion isn't here because it's automatic in
// this tool, matching v2rayN's own behavior — see the route section of
// buildConfig.)
const ISOLATED_FIELDS = ["ruleSetPath", "bypassApps"];
const PLATFORM_DEFAULTS = {
  windows: {
    ruleSetPath: "C:\\sing-box\\geosite-private.srs",
    bypassApps: ""
  },
  linux: {
    ruleSetPath: "/etc/sing-box/geosite-private.srs",
    bypassApps: ""
  }
};
function defaultRuleSetPath(platform) {
  return (PLATFORM_DEFAULTS[platform] || PLATFORM_DEFAULTS.windows).ruleSetPath;
}

// ---------- state ----------
let parsedOutbounds = [];   // array of { tag, config, warnings: [] }
let lastConfig = null;

// ============================================================
// VLESS URL PARSING
// ============================================================
function parseVlessLink(raw, index) {
  raw = raw.trim();
  const warnings = [];
  if (!raw) return null;

  const m = raw.match(/^vless:\/\/([^@]+)@([^:/?#\s]+):(\d+)(\?[^#]*)?(#.*)?$/i);
  if (!m) {
    return { ok: false, raw, error: "Doesn't match vless://uuid@host:port shape." };
  }

  const uuid = decodeURIComponent(m[1]);
  const host = m[2];
  const port = parseInt(m[3], 10);
  const query = new URLSearchParams(m[4] ? m[4].slice(1) : "");
  const remarkRaw = m[5] ? decodeURIComponent(m[5].slice(1)) : "";
  const tag = sanitizeTag(remarkRaw || `proxy-${index + 1}`, index);

  if (!UUID_RE.test(uuid)) {
    warnings.push(`UUID "${uuid}" doesn't look like a standard UUID — double check the link.`);
  }
  if (!port || port < 1 || port > 65535) {
    warnings.push(`Port "${m[3]}" is out of range.`);
  }

  const security = (query.get("security") || "none").toLowerCase();
  const network = (query.get("type") || "tcp").toLowerCase();
  let flow = query.get("flow") || "";
  // v2rayN normalizes both vision variants to the same flow value.
  if (flow === "xtls-rprx-vision-udp443") flow = "xtls-rprx-vision";
  const sni = query.get("sni") || query.get("peer") || "";
  const fp = query.get("fp") || "";
  const alpnParam = query.get("alpn");

  const outbound = {
    type: "vless",
    tag,
    server: host,
    server_port: port,
    uuid,
    packet_encoding: "xudp"
  };

  if (flow) {
    if (security !== "reality" && security !== "tls") {
      warnings.push(`"flow=${flow}" normally requires TLS/Reality; the link has security=${security}.`);
    }
    if (network !== "tcp" && network !== "raw") {
      warnings.push(`"flow" only applies to raw TCP transport; this link uses "${network}" and flow will be dropped.`);
    } else {
      outbound.flow = flow;
    }
  }

  // ---- Transport (parsed before TLS so its host header can feed the SNI
  // fallback below — matches v2rayN's own per-transport SNI derivation,
  // rather than a single flat query-param fallback) ----
  let transportHost = "";
  if (network === "ws") {
    let path = query.get("path") || "/";
    let earlyData = null;
    const edMatch = path.match(/[?&]ed=(\d+)/);
    if (edMatch) {
      earlyData = parseInt(edMatch[1], 10);
      path = path.replace(/[?&]ed=\d+/, "") || "/";
    }
    const transport = { type: "ws", path };
    const hostHeader = query.get("host");
    if (hostHeader) { transport.headers = { Host: hostHeader }; transportHost = hostHeader; }
    if (earlyData) {
      transport.max_early_data = earlyData;
      transport.early_data_header_name = "Sec-WebSocket-Protocol";
    }
    outbound.transport = transport;
  } else if (network === "grpc") {
    outbound.transport = {
      type: "grpc",
      service_name: query.get("serviceName") || query.get("path") || ""
    };
  } else if (network === "http" || network === "h2") {
    transportHost = query.get("host") || sni || outbound.server;
    outbound.transport = {
      type: "http",
      host: [transportHost],
      path: query.get("path") || "/"
    };
  } else if (network === "httpupgrade") {
    transportHost = query.get("host") || sni || outbound.server;
    outbound.transport = {
      type: "httpupgrade",
      host: transportHost,
      path: query.get("path") || "/"
    };
  } else if (network === "tcp" || network === "raw" || network === "") {
    const headerType = query.get("headerType");
    if (headerType && headerType !== "none") {
      warnings.push(`headerType="${headerType}" (raw TCP obfuscation) has no direct sing-box equivalent and was skipped.`);
    }
  } else {
    warnings.push(`Transport "${network}" isn't handled by this tool yet — generated as raw TCP.`);
  }

  // ---- TLS / Reality ----
  if (security === "tls" || security === "reality") {
    const tls = {
      enabled: true,
      server_name: sni || transportHost || outbound.server,
      insecure: query.get("allowInsecure") === "1"
    };
    if (alpnParam) tls.alpn = alpnParam.split(",").map(s => s.trim()).filter(Boolean);
    // v2rayN only sets utls if the link itself specifies a fingerprint —
    // it doesn't force one. An optional "force fingerprint" tool setting
    // can still add one afterward (see buildConfig), clearly as this
    // tool's own addition, not something read from the link.
    if (fp) tls.utls = { enabled: true, fingerprint: fp };

    if (security === "reality") {
      const pbk = query.get("pbk") || "";
      const sid = query.get("sid") || "";
      if (!pbk) warnings.push("Reality is enabled but the link has no pbk (public key) — the outbound will fail to connect.");
      tls.reality = { enabled: true, public_key: pbk, short_id: sid };
    }
    outbound.tls = tls;
  } else if (security && security !== "none") {
    warnings.push(`Unrecognized security="${security}" — treated as no TLS.`);
  }

  return {
    ok: true,
    tag,
    name: remarkRaw || tag,
    host: outbound.server,
    port,
    security,
    network,
    outbound,
    warnings
  };
}

// Reduces a CIDR to a single-address prefix (/32 for IPv4, /128 for IPv6) —
// used for TUN self-loop protection, so the reject rule matches only the
// TUN's own literal address rather than the whole subnet (see the route
// section of buildConfig for why that distinction matters on Linux).
function toSingleAddressPrefix(cidr) {
  const addr = cidr.split("/")[0];
  return addr.includes(":") ? `${addr}/128` : `${addr}/32`;
}

function sanitizeTag(name, index) {
  let t = name.trim().toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!t) t = `proxy-${index + 1}`;
  return t.slice(0, 40);
}

// ============================================================
// BYPASS DOMAIN PARSING
// One line per rule. Prefixes: "regex:", "keyword:". A leading "."
// keeps sing-box's literal-suffix behavior (subdomains only); a bare
// domain matches the domain itself and all subdomains (sing-box >=1.9).
// ============================================================
function parseBypassDomains(text) {
  const domain_suffix = [];
  const domain_keyword = [];
  const domain_regex = [];
  const warnings = [];

  // sing-box matches domain_suffix/domain_keyword as plain strings against
  // the sniffed SNI/Host — not a URL — so anything shaped like a URL has to
  // be reduced to a bare hostname first or it will silently never match.
  function normalizeHost(input) {
    let d = input.trim();
    d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");   // strip scheme, e.g. https://
    d = d.split(/[/?#]/)[0];                          // strip path/query/fragment
    d = d.replace(/:\d+$/, "");                       // strip :port
    d = d.replace(/\.$/, "");                         // strip trailing dot
    return d.toLowerCase();
  }

  text.split("\n").forEach(raw => {
    let line = raw.trim();
    if (!line || line.startsWith("#")) return;

    if (line.toLowerCase().startsWith("regex:")) {
      const pattern = line.slice(6).trim();
      if (!pattern) { warnings.push("Empty regex rule — skipped."); return; }
      try { new RegExp(pattern); domain_regex.push(pattern); }
      catch { warnings.push(`Bypass rule "${line}" isn't a valid regular expression — skipped.`); }
      return;
    }

    if (line.toLowerCase().startsWith("keyword:")) {
      const kw = normalizeHost(line.slice(8));
      if (kw) domain_keyword.push(kw); else warnings.push("Empty keyword rule — skipped.");
      return;
    }

    // "*.example.com" is a common wildcard convention elsewhere; sing-box's
    // own convention for "subdomains only, not the bare domain" is a
    // leading dot, so translate one into the other.
    let subdomainsOnly = false;
    if (line.startsWith("*.")) { subdomainsOnly = true; line = line.slice(2); }
    else if (line.startsWith(".")) { subdomainsOnly = true; line = line.slice(1); }

    const host = normalizeHost(line);
    if (!host) { warnings.push(`Bypass rule "${raw.trim()}" didn't leave a usable domain after cleanup — skipped.`); return; }
    if (!/^[a-z0-9.-]+$/.test(host) || !host.includes(".")) {
      warnings.push(`"${raw.trim()}" doesn't look like a plain domain (paste just the hostname, not a full URL) — kept as-is, double check it.`);
    }
    domain_suffix.push(subdomainsOnly ? `.${host}` : host);
  });

  return { domain_suffix, domain_keyword, domain_regex, warnings };
}

// ============================================================
// BYPASS APPLICATION PARSING
// One process name (or full path — only the filename is kept) per line.
// sing-box's process_name route field matches the executable's file name.
// Validation differs by platform: Windows needs the .exe extension; Linux
// process names are extension-less and the kernel truncates /proc/[pid]/comm
// to 15 characters, so a longer name may silently fail to match.
// ============================================================
function parseBypassApps(text, platform) {
  const processNames = [];
  const warnings = [];

  text.split("\n").forEach(raw => {
    let line = raw.trim();
    if (!line || line.startsWith("#")) return;

    // Accept a full path (Windows or POSIX-style) and reduce it to the
    // executable's file name, since that's what process_name matches on.
    line = line.replace(/^["']|["']$/g, "");
    const base = line.split(/[\\/]/).pop().trim();
    if (!base) { warnings.push(`Bypass app rule "${raw.trim()}" didn't leave a usable name — skipped.`); return; }
    if (platform === "linux") {
      if (/\.exe$/i.test(base)) {
        warnings.push(`"${base}" has a .exe extension — Linux process names usually don't. Double check this is the right binary name.`);
      }
      if (base.length > 15) {
        warnings.push(`"${base}" is longer than 15 characters — the Linux kernel truncates process names to 15 chars in /proc, so this may not match. Try the truncated form if it doesn't work.`);
      }
    } else if (!/\.exe$/i.test(base)) {
      warnings.push(`"${base}" doesn't end in .exe — process_name matching needs the exact executable file name on Windows.`);
    }
    processNames.push(base);
  });

  return { processNames: [...new Set(processNames)], warnings };
}

// ============================================================
// SELF-PROCESS EXCLUSION PATHS
// Full binary paths (not reduced to filename — process_path needs the
// exact path, unlike process_name above) for excluding this proxy client's
// own traffic from its own TUN, as extra safety alongside
// route.auto_detect_interface. One full path per line.
// ============================================================
// ============================================================
// CONFIG BUILDER
// ============================================================
function buildConfig(entries, opts) {
  const okEntries = entries.filter(e => e.ok);
  const outbounds = okEntries.map(e => ({ ...e.outbound }));

  // Optional, off by default — v2rayN itself never forces a fingerprint if
  // the link doesn't specify one (see parseVlessLink). This is this tool's
  // own addition for people who want the older hardening behavior back.
  if (opts.forceFingerprint) {
    outbounds.forEach(o => {
      if (o.tls && o.tls.enabled && !o.tls.utls) {
        o.tls.utls = { enabled: true, fingerprint: opts.forceFingerprint };
      }
    });
  }

  const bypass = opts.bypass || { domain_suffix: [], domain_keyword: [], domain_regex: [] };
  const hasBypass = bypass.domain_suffix.length || bypass.domain_keyword.length || bypass.domain_regex.length;
  const bypassFields = {};
  if (bypass.domain_suffix.length) bypassFields.domain_suffix = bypass.domain_suffix;
  if (bypass.domain_keyword.length) bypassFields.domain_keyword = bypass.domain_keyword;
  if (bypass.domain_regex.length) bypassFields.domain_regex = bypass.domain_regex;

  const bypassApps = opts.bypassApps || { processNames: [] };
  const hasBypassApps = bypassApps.processNames.length > 0;

  // dedupe tags
  const seen = new Map();
  outbounds.forEach(o => {
    const base = o.tag;
    let n = seen.get(base) || 0;
    if (n > 0) o.tag = `${base}-${n + 1}`;
    seen.set(base, n + 1);
  });

  const useSelector = outbounds.length > 1;
  const proxyTag = "proxy";

  // ---------- DNS (v2rayN-faithful architecture) ----------
  // Ported from GenDnsServers()/GenBootstrapDns() in SingboxDnsService.cs:
  // a small bootstrap resolver (plain IP by default, no DoH — avoids any
  // chicken-and-egg problem) resolves the remote/direct DNS servers' own
  // hostnames, UNLESS that hostname happens to be in the static hosts
  // table, in which case hosts_dns is used instead (no network round trip
  // at all). This means ANY custom DoH provider works out of the box, not
  // just the four hardcoded ones — the gap that motivated this rewrite.
  const bootstrapAddr = opts.bootstrapDns === "custom" ? opts.bootstrapDnsCustom
    : opts.bootstrapDns === "system" ? "local"
    : opts.bootstrapDns;
  const directAddr = opts.directDns === "custom" ? opts.directDnsCustom
    : opts.directDns === "system" ? "local"
    : opts.directDns;
  const remoteAddr = opts.remoteDns === "custom" ? opts.remoteDnsCustom : opts.remoteDns;

  const bootstrapDns = parseDnsAddress(bootstrapAddr) || { type: "local" };
  bootstrapDns.tag = "bootstrap_dns";

  const directDns = parseDnsAddress(directAddr) || { type: "local" };
  directDns.tag = "direct_dns";
  if (directDns.type !== "local" && directDns.type !== "dhcp") {
    directDns.domain_resolver = "bootstrap_dns";
  }

  const remoteDns = parseDnsAddress(remoteAddr) || { type: "https", server: "cloudflare-dns.com", path: "/dns-query" };
  remoteDns.tag = "remote_dns";
  remoteDns.detour = proxyTag;
  if (remoteDns.type !== "local" && remoteDns.type !== "dhcp") {
    remoteDns.domain_resolver = "bootstrap_dns";
  }

  const hostsEntries = { ...V2RAYN_PREDEFINED_HOSTS };
  if (opts.remoteDns === "custom" && opts.remoteDnsCustom) hostsEntries[remoteDns.server] = hostsEntries[remoteDns.server] || [];
  if (opts.directDns === "custom" && opts.directDnsCustom) hostsEntries[directDns.server] = hostsEntries[directDns.server] || [];

  // Graceful hosts override: switch domain_resolver to hosts_dns for any
  // of the three servers whose own hostname is in the predefined table —
  // exact port of the `foreach (var host in hostsDns.predefined)` loop.
  [bootstrapDns, remoteDns, directDns].forEach(s => {
    if (s.server && hostsEntries[s.server]) s.domain_resolver = "hosts_dns";
  });

  const dnsServers = [bootstrapDns, remoteDns, directDns, {
    predefined: hostsEntries,
    type: "hosts",
    tag: "hosts_dns"
  }];

  const strategy = opts.dnsStrategy || undefined;
  const dnsRules = [
    { server: "hosts_dns", ip_accept_any: true },
    { server: "remote_dns", strategy, clash_mode: "Global" },
    { server: "direct_dns", strategy, clash_mode: "Direct" },
    { action: "predefined", rcode: "NOERROR", query_type: [64, 65] }
  ];
  if (hasBypass) {
    dnsRules.push({ server: "direct_dns", strategy, ...bypassFields });
  }
  if (hasBypassApps) {
    dnsRules.push({ server: "direct_dns", strategy, process_name: bypassApps.processNames });
  }
  if (opts.useGeositePrivate) {
    dnsRules.push({ server: "direct_dns", strategy, rule_set: ["geosite-private"] });
  }

  const dns = {
    servers: dnsServers,
    rules: dnsRules,
    final: "remote_dns",
    independent_cache: true
  };

  // ---------- inbounds ----------
  const inbounds = [];
  if (opts.socksEnable) {
    inbounds.push({
      type: "mixed",
      tag: "socks",
      listen: "127.0.0.1",
      listen_port: opts.socksPort
    });
  }
  inbounds.push({
    type: "tun",
    tag: "tun",
    interface_name: opts.tunName,
    address: [opts.tunAddr],
    mtu: opts.tunMtu,
    auto_route: true,
    strict_route: opts.strictRoute,
    stack: opts.tunStack
  });

  // ---------- outbounds ----------
  const finalOutbounds = [...outbounds];
  if (useSelector) {
    finalOutbounds.unshift({
      type: "selector",
      tag: proxyTag,
      outbounds: outbounds.map(o => o.tag),
      default: outbounds[0].tag
    });
  } else if (outbounds.length === 1) {
    outbounds[0].tag = proxyTag;
  }
  finalOutbounds.push({ type: "direct", tag: "direct" });

  // ---------- route ----------
  const ruleSet = opts.ruleSetMode === "remote"
    ? {
        tag: "geosite-private",
        type: "remote",
        format: "binary",
        url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs",
        download_detour: "direct"
      }
    : {
        tag: "geosite-private",
        type: "local",
        format: "binary",
        path: opts.ruleSetPath
      };

  const routeRules = [];

  {
    // TUN self-loop protection, ported from GenRouting(): auto_route
    // hijacks the default route, so if a packet addressed to the TUN
    // interface's own address ever reaches "direct", it gets written
    // straight back into the TUN and handed to the outbound again — an
    // infinite loop pinning a CPU core. Drop (not reject) so no ICMP
    // unreachable reply is generated back toward the same address, which
    // would loop the same way. Matched per-address, not by CIDR prefix:
    // on Linux, sing-tun registers the next address after the TUN's own
    // first address with systemd-resolved as a DNS upstream, and since
    // every prefix here is a /30 or /126, matching the prefix would also
    // drop every system DNS lookup through that resolver.
    const tunAddrs = [opts.tunAddr].filter(Boolean).map(toSingleAddressPrefix);
    if (tunAddrs.length) {
      routeRules.push({ ip_cidr: tunAddrs, action: "reject", method: "drop" });
    }

    // Automatic self-process exclusion — v2rayN never asks for this; it
    // always excludes its own sing-box binary by process name, matching
    // the platform's own executable naming.
    const selfExe = opts.platform === "linux" ? "sing-box" : "sing-box.exe";
    routeRules.push({ port: [53], action: "hijack-dns", process_name: [selfExe] });
    routeRules.push({ outbound: "direct", process_name: [selfExe] });

    // ICMP routing policy
    const icmp = opts.icmpRouting || "rule";
    if (icmp === "direct") {
      routeRules.push({ network: ["icmp"], outbound: "direct" });
    } else if (icmp !== "rule") {
      const method = icmp === "unreachable" ? "default" : icmp === "drop" ? "drop" : "reply";
      routeRules.push({ network: ["icmp"], action: "reject", method });
    }
  }

  routeRules.push(
    { action: "sniff" },
    {
      type: "logical", mode: "or",
      rules: [{ port: [53] }, { protocol: ["dns"] }],
      action: "hijack-dns"
    }
  );
  if (opts.tlsFragment) {
    routeRules.push({ protocol: ["tls"], action: "route-options", tls_record_fragment: true });
  }
  routeRules.push(
    { outbound: "direct", clash_mode: "Direct" },
    { outbound: proxyTag, clash_mode: "Global" }
  );
  if (opts.blockQuic) {
    routeRules.push({ network: ["udp"], port: [443], action: "reject" });
  }
  if (opts.blockIpv6) {
    routeRules.push({ ip_version: 6, action: "reject" });
  }
  routeRules.push({ outbound: "direct", ip_is_private: true });
  if (hasBypass) {
    routeRules.push({ outbound: "direct", ...bypassFields });
  }
  if (hasBypassApps) {
    routeRules.push({ outbound: "direct", process_name: bypassApps.processNames });
  }
  if (opts.useGeositePrivate) {
    routeRules.push({ outbound: "direct", rule_set: ["geosite-private"] });
  }
  routeRules.push({ outbound: proxyTag, port_range: ["0:65535"] });

  // default_domain_resolver always points at direct_dns in v2rayN's simple
  // DNS mode (GenRouting(): defaultDomainResolverTag = SingboxDirectDNSTag),
  // carrying the dial-time strategy — not conditional on any "do we have a
  // direct resolver" check, since direct_dns always exists now.
  const route = {
    default_domain_resolver: { server: "direct_dns", strategy: opts.dnsStrategy || undefined },
    auto_detect_interface: true,
    rules: routeRules,
    final: proxyTag
  };
  if (opts.useGeositePrivate) {
    route.rule_set = [ruleSet];
  }

  // ---------- experimental ----------
  const experimental = {};
  if (opts.cacheFile) {
    experimental.cache_file = { enabled: true, path: "cache.db", store_fakeip: false };
  }
  if (opts.clashApi) {
    experimental.clash_api = { external_controller: `127.0.0.1:${opts.clashPort}` };
    if (opts.clashSecret) experimental.clash_api.secret = opts.clashSecret;
  }

  const config = {
    log: { level: opts.logLevel, timestamp: true },
    dns,
    inbounds,
    outbounds: finalOutbounds,
    endpoints: [],
    route,
    experimental
  };

  return config;
}

// ============================================================
// JSON SYNTAX HIGHLIGHT (lightweight, no deps)
// ============================================================
function highlightJson(json) {
  const esc = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(
    /("(\\.|[^"\\])*"(\s*:)?|\b(true|false|null)\b|-?\d+\.?\d*(e[+-]?\d+)?)/gi,
    (match) => {
      if (/^"/.test(match)) {
        return /:$/.test(match)
          ? `<span class="tok-key">${match.slice(0, -1)}</span><span class="tok-punc">:</span>`
          : `<span class="tok-str">${match}</span>`;
      }
      if (/true|false/.test(match)) return `<span class="tok-bool">${match}</span>`;
      if (/null/.test(match)) return `<span class="tok-punc">${match}</span>`;
      return `<span class="tok-num">${match}</span>`;
    }
  );
}

// ============================================================
// UI WIRING
// ============================================================
const els = {
  input: document.getElementById("vlessInput"),
  parseBtn: document.getElementById("parseBtn"),
  sampleBtn: document.getElementById("sampleBtn"),
  parseStatus: document.getElementById("parseStatus"),
  linkResults: document.getElementById("linkResults"),
  output: document.getElementById("output"),
  outputCode: document.getElementById("outputCode"),
  copyBtn: document.getElementById("copyBtn"),
  downloadBtn: document.getElementById("downloadBtn"),
  warnings: document.getElementById("warnings"),
};

const optionEls = {
  platform: document.getElementById("optPlatform"),
  bootstrapDns: document.getElementById("optBootstrapDns"),
  bootstrapDnsCustom: document.getElementById("optBootstrapDnsCustom"),
  directDns: document.getElementById("optDirectDns"),
  directDnsCustom: document.getElementById("optDirectDnsCustom"),
  remoteDns: document.getElementById("optRemoteDns"),
  remoteDnsCustom: document.getElementById("optRemoteDnsCustom"),
  dnsStrategy: document.getElementById("optDnsStrategy"),
  forceFingerprint: document.getElementById("optForceFingerprint"),
  blockQuic: document.getElementById("optBlockQuic"),
  blockIpv6: document.getElementById("optBlockIpv6"),
  tunAddr: document.getElementById("optTunAddr"),
  tunStack: document.getElementById("optTunStack"),
  strictRoute: document.getElementById("optStrictRoute"),
  icmpRouting: document.getElementById("optIcmpRouting"),
  tlsFragment: document.getElementById("optTlsFragment"),
  socksEnable: document.getElementById("optSocksEnable"),
  socksPort: document.getElementById("optSocksPort"),
  clashApi: document.getElementById("optClashApi"),
  clashPort: document.getElementById("optClashPort"),
  clashSecret: document.getElementById("optClashSecret"),
  ruleSetMode: document.getElementById("optRuleSetMode"),
  useGeositePrivate: document.getElementById("optUseGeositePrivate"),
  ruleSetPath: document.getElementById("optRuleSetPath"),
  cacheFile: document.getElementById("optCacheFile"),
  bypassDomains: document.getElementById("optBypassDomains"),
  bypassApps: document.getElementById("optBypassApps"),
};

// ============================================================
// PLATFORM PROFILE ISOLATION
// Each platform gets its own independent copy of the fields whose content
// is shaped for one OS and wrong-shaped for the other. Switching platforms
// swaps between two separate stashes rather than leaving stale content
// (Windows .exe names while Linux is selected, etc.) sitting in the field.
// Unlike index.html/linux.html, this is a single page with a real,
// live-switchable platform selector — not a fixed-platform page pair — so
// there's no cross-page localStorage contamination risk to guard against
// here; a restored "platform" value is trusted directly.
// ============================================================
const platformProfiles = {
  windows: { ...PLATFORM_DEFAULTS.windows },
  linux: { ...PLATFORM_DEFAULTS.linux }
};
let currentPlatformTracker = optionEls.platform.value || "windows";

function syncCurrentPlatformProfile() {
  const p = platformProfiles[currentPlatformTracker] || (platformProfiles[currentPlatformTracker] = {});
  ISOLATED_FIELDS.forEach(key => {
    const el = optionEls[key];
    if (el) p[key] = getOptionValue(el);
  });
}

function loadPlatformProfile(platform) {
  const defaults = PLATFORM_DEFAULTS[platform] || PLATFORM_DEFAULTS.windows;
  const p = platformProfiles[platform] || defaults;
  ISOLATED_FIELDS.forEach(key => {
    const el = optionEls[key];
    if (el) setOptionValue(el, key in p ? p[key] : defaults[key]);
  });
}

function switchPlatformProfile(newPlatform) {
  if (newPlatform === currentPlatformTracker) return;
  syncCurrentPlatformProfile();
  loadPlatformProfile(newPlatform);
  currentPlatformTracker = newPlatform;
}

// ============================================================
// SETTINGS PERSISTENCE
// Saves option fields (not the pasted vless links — those carry UUIDs/keys,
// and re-pasting one link is trivial compared to re-entering everything
// else) to localStorage, so a reload doesn't wipe 20+ configured fields.
// Uses its own storage key, distinct from the other pages' tool, since the
// field sets genuinely differ (bootstrap/direct DNS vs. local/DoH mode,
// no manual self-process field here).
// ============================================================
const SETTINGS_STORAGE_KEY = "configforge:v2rayn:options:v1";

// Snapshot the HTML-authored defaults now, before any restore runs, so
// "reset to defaults" has a true baseline to return to.
const defaultOptionValues = {};
Object.entries(optionEls).forEach(([key, el]) => {
  if (!el) return;
  defaultOptionValues[key] = el.type === "checkbox" ? el.checked : el.value;
});

function getOptionValue(el) {
  return el.type === "checkbox" ? el.checked : el.value;
}
function setOptionValue(el, value) {
  if (el.type === "checkbox") el.checked = !!value;
  else el.value = value;
}

function saveSettings() {
  try {
    syncCurrentPlatformProfile();
    const snapshot = {};
    Object.entries(optionEls).forEach(([key, el]) => {
      if (el) snapshot[key] = getOptionValue(el);
    });
    snapshot.__platformProfiles = platformProfiles;
    localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(snapshot));
    flashSettingsStatus("saved");
  } catch {
    // localStorage unavailable (private browsing, disabled storage, etc.) —
    // fail silently, the tool still works without persistence.
  }
}

function restoreSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return false;
    const snapshot = JSON.parse(raw);
    Object.entries(optionEls).forEach(([key, el]) => {
      if (el && key in snapshot) setOptionValue(el, snapshot[key]);
    });
    if (snapshot.__platformProfiles) {
      Object.assign(platformProfiles.windows, snapshot.__platformProfiles.windows || {});
      Object.assign(platformProfiles.linux, snapshot.__platformProfiles.linux || {});
    }
    // Isolated fields are authoritatively owned by the profile store, not
    // the flat snapshot above — load from the profile for whichever
    // platform was restored, so the two stay consistent.
    currentPlatformTracker = optionEls.platform.value || "windows";
    loadPlatformProfile(currentPlatformTracker);
    return true;
  } catch {
    return false;
  }
}

function resetSettingsToDefaults() {
  Object.entries(optionEls).forEach(([key, el]) => {
    if (el) setOptionValue(el, defaultOptionValues[key]);
  });
  platformProfiles.windows = { ...PLATFORM_DEFAULTS.windows };
  platformProfiles.linux = { ...PLATFORM_DEFAULTS.linux };
  currentPlatformTracker = optionEls.platform.value || "windows";
  try { localStorage.removeItem(SETTINGS_STORAGE_KEY); } catch { /* ignore */ }
  applyConditionalVisibility();
  applyPlatformDefaults();
  regenerate();
  flashSettingsStatus("reset to defaults");
}

let settingsStatusTimer = null;
function flashSettingsStatus(text) {
  const el = document.getElementById("settingsStatus");
  if (!el) return;
  el.textContent = text;
  el.className = "parse-status ok";
  clearTimeout(settingsStatusTimer);
  settingsStatusTimer = setTimeout(() => { el.textContent = ""; }, 1800);
}

// Recomputes every conditional show/hide field based on current values —
// shared by initial load, restore, and reset, so they can't drift apart.
function applyConditionalVisibility() {
  optionEls.remoteDnsCustom.hidden = optionEls.remoteDns.value !== "custom";
  optionEls.bootstrapDnsCustom.hidden = optionEls.bootstrapDns.value !== "custom";
  optionEls.directDnsCustom.hidden = optionEls.directDns.value !== "custom";
  const geositeOn = optionEls.useGeositePrivate.checked;
  document.getElementById("ruleSetModeRow").hidden = !geositeOn;
  optionEls.ruleSetPath.hidden = !geositeOn || optionEls.ruleSetMode.value !== "local";
  document.getElementById("socksPortRow").style.opacity = optionEls.socksEnable.checked ? "1" : "0.4";
  const clashOn = optionEls.clashApi.checked;
  document.getElementById("clashPortRow").style.opacity = clashOn ? "1" : "0.4";
  document.getElementById("clashSecretRow").style.opacity = clashOn ? "1" : "0.4";
}

// Updates copy that differs by target OS. Isolated-field values themselves
// (ruleSetPath, bypassApps) are handled by switchPlatformProfile(), not
// here — this only updates text/labels.
function applyPlatformDefaults() {
  const platform = optionEls.platform.value;
  const isLinux = platform === "linux";

  const pill = document.getElementById("platformPill");
  if (pill) pill.textContent = `target: sing-box · ${isLinux ? "linux" : "windows"}`;

  const hint = document.getElementById("platformHint");
  if (hint) {
    hint.textContent = isLinux
      ? "TUN mode needs elevated capabilities — run as root, or grant the binary CAP_NET_ADMIN/CAP_NET_RAW (and CAP_SYS_PTRACE if using bypass applications) via setcap."
      : "TUN mode needs Administrator — right-click sing-box (or your terminal) and \"Run as administrator\".";
  }

  const bLabel = document.getElementById("bypassAppsLabel");
  if (bLabel) bLabel.textContent = isLinux ? "One Linux process name per line." : "One Windows executable per line.";

  const bHint = document.getElementById("bypassAppsHint");
  if (bHint) {
    bHint.innerHTML = isLinux
      ? 'Matches by process name (e.g. <code>steam</code>) — a full path is fine too, only the filename is used. Linux truncates process names to 15 characters internally. Useful for apps that break under a VPN/TUN.'
      : 'Matches by process name (e.g. <code>steam.exe</code>) — a full path is fine too, only the filename is used. Useful for apps that break under a VPN/TUN, like games with anti-cheat or LAN-discovery tools.';
  }

  optionEls.bypassApps.placeholder = isLinux
    ? "steam\ndiscord\n/usr/bin/some-launcher"
    : "steam.exe\nEpicGamesLauncher.exe\nC:\\Program Files\\App\\app.exe";

  const lede = document.getElementById("ledeText");
  if (lede) {
    lede.innerHTML = `Paste one or more <code>vless://</code> links. Config Forge builds a sing-box config for the ${isLinux ? "Linux" : "Windows"} client — TUN inbound, DNS over HTTPS routed through your own proxy, and a fail-closed route table — using the same shape as a v2rayN-generated config. Nothing leaves this tab: the conversion runs locally in JavaScript.`;
  }
}

function readOptions() {
  return {
    platform: optionEls.platform.value,
    remoteDns: optionEls.remoteDns.value,
    remoteDnsCustom: optionEls.remoteDnsCustom.value.trim(),
    bootstrapDns: optionEls.bootstrapDns.value,
    bootstrapDnsCustom: optionEls.bootstrapDnsCustom.value.trim(),
    directDns: optionEls.directDns.value,
    directDnsCustom: optionEls.directDnsCustom.value.trim(),
    dnsStrategy: optionEls.dnsStrategy.value,
    forceFingerprint: optionEls.forceFingerprint.value,
    blockQuic: optionEls.blockQuic.checked,
    blockIpv6: optionEls.blockIpv6.checked,
    tunName: FIXED_TUN_NAME,
    tunAddr: optionEls.tunAddr.value.trim() || "172.18.0.1/30",
    tunMtu: FIXED_TUN_MTU,
    tunStack: optionEls.tunStack.value,
    strictRoute: optionEls.strictRoute.checked,
    icmpRouting: optionEls.icmpRouting.value,
    tlsFragment: optionEls.tlsFragment.checked,
    socksEnable: optionEls.socksEnable.checked,
    socksPort: parseInt(optionEls.socksPort.value, 10) || 10808,
    clashApi: optionEls.clashApi.checked,
    clashPort: parseInt(optionEls.clashPort.value, 10) || 10814,
    clashSecret: optionEls.clashSecret.value.trim(),
    ruleSetMode: optionEls.ruleSetMode.value,
    useGeositePrivate: optionEls.useGeositePrivate.checked,
    ruleSetPath: optionEls.ruleSetPath.value.trim() || defaultRuleSetPath(optionEls.platform.value),
    logLevel: FIXED_LOG_LEVEL,
    cacheFile: optionEls.cacheFile.checked,
  };
}

// conditional field visibility
optionEls.platform.addEventListener("change", () => {
  switchPlatformProfile(optionEls.platform.value);
  applyPlatformDefaults();
});
optionEls.remoteDns.addEventListener("change", applyConditionalVisibility);
optionEls.bootstrapDns.addEventListener("change", applyConditionalVisibility);
optionEls.directDns.addEventListener("change", applyConditionalVisibility);
optionEls.ruleSetMode.addEventListener("change", applyConditionalVisibility);
optionEls.useGeositePrivate.addEventListener("change", applyConditionalVisibility);
optionEls.socksEnable.addEventListener("change", applyConditionalVisibility);
optionEls.clashApi.addEventListener("change", applyConditionalVisibility);

Object.values(optionEls).forEach(el => {
  if (!el) return;
  const evt = (el.tagName === "SELECT" || el.type === "checkbox") ? "change" : "input";
  el.addEventListener(evt, () => { regenerate(); saveSettings(); });
});

document.getElementById("resetOptionsBtn").addEventListener("click", resetSettingsToDefaults);

function setNodeState(node, state) {
  const el = document.querySelector(`.path-node[data-node="${node}"]`);
  if (el) el.dataset.state = state;
}
function setWireActive(n, active) {
  const el = document.querySelector(`.path-wire[data-wire="${n}"]`);
  if (el) el.dataset.active = active ? "1" : "0";
}

function updateSignalPath(entries, opts) {
  const okEntries = entries.filter(e => e.ok);
  const hasLink = okEntries.length > 0;
  const hasTls = okEntries.some(e => e.security === "tls" || e.security === "reality");

  setNodeState("link", hasLink ? "active" : "idle");
  setNodeState("tls", hasLink ? (hasTls ? "active" : "warn") : "idle");
  setNodeState("dns", hasLink ? "active" : "idle");
  setNodeState("route", hasLink ? "active" : "idle");
  setNodeState("out", hasLink ? "active" : "idle");

  setWireActive(1, hasLink);
  setWireActive(2, hasLink);
  setWireActive(3, hasLink);
  setWireActive(4, hasLink);
}

function renderLinkResults(entries) {
  els.linkResults.innerHTML = "";
  entries.forEach(e => {
    const card = document.createElement("div");
    if (!e.ok) {
      card.className = "link-card err";
      card.innerHTML = `
        <div class="link-card-main">
          <div class="link-card-name">unparsed link</div>
          <div class="link-card-detail">${escapeHtml(e.error)}</div>
        </div>
        <span class="link-card-badge badge-err">error</span>`;
    } else {
      card.className = "link-card";
      const detail = `${e.host}:${e.port} · ${e.security} · ${e.network}${e.warnings.length ? " · " + e.warnings.length + " warning(s)" : ""}`;
      card.innerHTML = `
        <div class="link-card-main">
          <div class="link-card-name">${escapeHtml(e.name)}</div>
          <div class="link-card-detail">${escapeHtml(detail)}</div>
        </div>
        <span class="link-card-badge ${e.warnings.length ? "badge-err" : "badge-ok"}">${e.warnings.length ? "check" : "ok"}</span>`;
    }
    els.linkResults.appendChild(card);
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function regenerate() {
  const raw = els.input.value;
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);

  if (lines.length === 0) {
    parsedOutbounds = [];
    updateSignalPath([], {});
    els.linkResults.innerHTML = "";
    return;
  }

  const entries = lines.map((line, i) => {
    if (!/^vless:\/\//i.test(line)) {
      return { ok: false, raw: line, error: "Doesn't start with vless://" };
    }
    try {
      return parseVlessLink(line, i);
    } catch (err) {
      return { ok: false, raw: line, error: err.message || "Failed to parse." };
    }
  });

  parsedOutbounds = entries;
  renderLinkResults(entries);
  updateSignalPath(entries, {});

  const okEntries = entries.filter(e => e.ok);
  const allWarnings = [];
  entries.forEach(e => {
    if (!e.ok) allWarnings.push(`Skipped a link: ${e.error}`);
    else e.warnings.forEach(w => allWarnings.push(`${e.name}: ${w}`));
  });

  if (okEntries.length === 0) {
    els.outputCode.textContent = "// no valid vless:// links yet";
    els.copyBtn.disabled = true;
    els.downloadBtn.disabled = true;
    renderWarnings(allWarnings);
    lastConfig = null;
    return;
  }

  const opts = readOptions();
  if (opts.bootstrapDns === "custom" && !opts.bootstrapDnsCustom) {
    allWarnings.push("Bootstrap resolver is set to \"Custom…\" but the field is empty — falling back to System default.");
  }
  if (opts.directDns === "custom" && !opts.directDnsCustom) {
    allWarnings.push("Direct resolver is set to \"Custom…\" but the field is empty — falling back to System default.");
  }
  const bypass = parseBypassDomains(optionEls.bypassDomains.value);
  bypass.warnings.forEach(w => allWarnings.push(w));
  opts.bypass = bypass;
  const bypassApps = parseBypassApps(optionEls.bypassApps.value, optionEls.platform.value);
  bypassApps.warnings.forEach(w => allWarnings.push(w));
  opts.bypassApps = bypassApps;
  const config = buildConfig(entries, opts);
  lastConfig = config;

  const json = JSON.stringify(config, null, 2);
  els.outputCode.innerHTML = highlightJson(json);
  els.copyBtn.disabled = false;
  els.downloadBtn.disabled = false;
  renderWarnings(allWarnings);
}

function renderWarnings(list) {
  if (list.length === 0) {
    els.warnings.hidden = true;
    els.warnings.innerHTML = "";
    return;
  }
  els.warnings.hidden = false;
  els.warnings.innerHTML = `<strong>heads up</strong><ul>${list.map(w => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`;
}

els.parseBtn.addEventListener("click", () => {
  regenerate();
  const okCount = parsedOutbounds.filter(e => e.ok).length;
  const errCount = parsedOutbounds.filter(e => !e.ok).length;
  els.parseStatus.textContent = parsedOutbounds.length
    ? `${okCount} parsed${errCount ? `, ${errCount} failed` : ""}`
    : "";
  els.parseStatus.className = "parse-status " + (errCount ? "err" : (okCount ? "ok" : ""));
});

els.sampleBtn.addEventListener("click", () => {
  els.input.value = "vless://d4b37f8e-d151-4baf-a38f-08553ad4430b@104.248.151.72:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=2K_uxUIqAyf-Nrw4pFVIwCbXXjx25dLj6FqYohHJ3yk&sid=4268081ad76bb1f0&sni=i.ytimg.com&fp=chrome#Sample-Reality-Server";
  regenerate();
});

els.copyBtn.addEventListener("click", async () => {
  if (!lastConfig) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastConfig, null, 2));
    const old = els.copyBtn.textContent;
    els.copyBtn.textContent = "copied";
    setTimeout(() => { els.copyBtn.textContent = old; }, 1400);
  } catch {
    els.copyBtn.textContent = "copy failed";
  }
});

els.downloadBtn.addEventListener("click", () => {
  if (!lastConfig) return;
  const blob = new Blob([JSON.stringify(lastConfig, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "config.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// initial state
restoreSettings();
applyConditionalVisibility();
applyPlatformDefaults();
