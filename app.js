/* ============================================================
   Config Forge — vless:// -> sing-box client config (Windows)
   Pure client-side. No network calls, no data leaves the tab.
   ============================================================ */

// ---------- DoH provider table ----------
// Each entry gives the DoH domain + a hosts-style predefined IP set,
// so the bootstrap lookup of the resolver's own hostname never needs
// an unencrypted DNS query (matches sing-box's recommended "hosts" pattern).
const DOH_PROVIDERS = {
  cloudflare: {
    domain: "cloudflare-dns.com",
    ips: ["104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"]
  },
  google: {
    domain: "dns.google",
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"]
  },
  quad9: {
    domain: "dns.quad9.net",
    ips: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]
  },
  alidns: {
    domain: "dns.alidns.com",
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"]
  }
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Fixed rather than user-editable — nobody meaningfully needs to change
// these, so they're no longer fields in the UI at all.
const FIXED_TUN_NAME = "singbox_tun";
const FIXED_TUN_MTU = 9000;
const FIXED_LOG_LEVEL = "warn";

// Path/process-name conventions differ by OS; the sing-box config.json
// schema itself does not. These three fields are the ones whose *content*
// is shaped for one platform and meaningless (or actively wrong) on the
// other, so each platform gets its own fully isolated copy — switching
// platforms swaps between two separate profiles rather than leaving stale
// Windows-shaped content sitting there while Linux is selected, or vice
// versa.
const ISOLATED_FIELDS = ["ruleSetPath", "bypassApps", "selfProcessPaths"];
const PLATFORM_DEFAULTS = {
  windows: {
    ruleSetPath: "C:\\sing-box\\geosite-private.srs",
    bypassApps: "",
    selfProcessPaths: ""
  },
  linux: {
    ruleSetPath: "/etc/sing-box/geosite-private.srs",
    bypassApps: "",
    selfProcessPaths: ""
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
  const flow = query.get("flow") || "";
  const sni = query.get("sni") || query.get("peer") || "";
  const fp = query.get("fp") || "chrome";
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

  // ---- TLS / Reality ----
  if (security === "tls" || security === "reality") {
    const tls = {
      enabled: true,
      server_name: sni || outbound.server,
      insecure: query.get("allowInsecure") === "1"
    };
    if (alpnParam) tls.alpn = alpnParam.split(",").map(s => s.trim()).filter(Boolean);
    tls.utls = { enabled: true, fingerprint: fp };

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

  // ---- Transport ----
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
    if (hostHeader) transport.headers = { Host: hostHeader };
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
    const hostHeader = query.get("host") || sni || outbound.server;
    outbound.transport = {
      type: "http",
      host: [hostHeader],
      path: query.get("path") || "/"
    };
  } else if (network === "httpupgrade") {
    outbound.transport = {
      type: "httpupgrade",
      host: query.get("host") || sni || outbound.server,
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
function parseSelfProcessPaths(text, platform) {
  const paths = [];
  const warnings = [];
  const looksAbsolute = platform === "linux"
    ? (p) => p.startsWith("/")
    : (p) => /^[a-zA-Z]:[\\/]/.test(p) || p.startsWith("\\\\");

  text.split("\n").forEach(raw => {
    const line = raw.trim().replace(/^["']|["']$/g, "");
    if (!line || line.startsWith("#")) return;
    if (!looksAbsolute(line)) {
      warnings.push(`"${line}" doesn't look like a full path — process_path needs the complete path to the binary, not just its name.`);
    }
    paths.push(line);
  });

  return { paths: [...new Set(paths)], warnings };
}

// ============================================================
// CONFIG BUILDER
// ============================================================
function buildConfig(entries, opts) {
  const okEntries = entries.filter(e => e.ok);
  const outbounds = okEntries.map(e => ({ ...e.outbound }));

  const bypass = opts.bypass || { domain_suffix: [], domain_keyword: [], domain_regex: [] };
  const hasBypass = bypass.domain_suffix.length || bypass.domain_keyword.length || bypass.domain_regex.length;
  const bypassFields = {};
  if (bypass.domain_suffix.length) bypassFields.domain_suffix = bypass.domain_suffix;
  if (bypass.domain_keyword.length) bypassFields.domain_keyword = bypass.domain_keyword;
  if (bypass.domain_regex.length) bypassFields.domain_regex = bypass.domain_regex;

  const bypassApps = opts.bypassApps || { processNames: [] };
  const hasBypassApps = bypassApps.processNames.length > 0;

  const useSystemDns = opts.localDns === "system";
  const useDirectDoh = opts.localDns === "doh";
  const localDnsIp = opts.localDns === "custom" ? opts.localDnsCustom
    : (useSystemDns || useDirectDoh) ? null
    : opts.localDns;
  const hasDirectResolver = useSystemDns || useDirectDoh || !!localDnsIp;

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

  // ---------- DNS ----------
  const remoteProvider = DOH_PROVIDERS[opts.remoteDns] ||
    { domain: opts.remoteDnsCustom || "cloudflare-dns.com", ips: [] };
  const localDohProvider = DOH_PROVIDERS[opts.localDohProvider] ||
    { domain: opts.localDohProviderCustom || "cloudflare-dns.com", ips: [] };

  const hostsEntries = {};
  Object.values(DOH_PROVIDERS).forEach(p => { hostsEntries[p.domain] = p.ips; });
  if (opts.remoteDns === "custom" && opts.remoteDnsCustom) {
    hostsEntries[opts.remoteDnsCustom] = [];
  }
  if (useDirectDoh && opts.localDohProvider === "custom" && opts.localDohProviderCustom) {
    hostsEntries[opts.localDohProviderCustom] = [];
  }

  const dnsServers = [];

  if (localDnsIp) {
    dnsServers.push({ server: localDnsIp, type: "udp", tag: "local_local" });
  }
  dnsServers.push({
    server: remoteProvider.domain,
    domain_resolver: "hosts_dns",
    path: "/dns-query",
    type: "https",
    tag: "remote_dns",
    detour: proxyTag
  });
  if (useDirectDoh) {
    // Independent of the remote provider choice above — if your network
    // blocks direct connections to one provider, pick a different one for
    // this untunneled path without having to change your remote resolver
    // too. Bootstrapped via the same hosts_dns predefined IPs.
    dnsServers.push({
      server: localDohProvider.domain,
      domain_resolver: "hosts_dns",
      path: "/dns-query",
      type: "https",
      tag: "direct_dns"
    });
  } else if (useSystemDns) {
    // Uses the OS's own resolver directly — matches what a browser would
    // get with no proxy running at all, avoiding geo/anycast mismatches
    // that a foreign DNS provider can cause for direct-routed domains.
    dnsServers.push({ type: "local", tag: "direct_dns" });
  } else if (localDnsIp) {
    dnsServers.push({ server: localDnsIp, domain_resolver: "local_local", type: "udp", tag: "direct_dns" });
  }
  dnsServers.push({
    predefined: hostsEntries,
    type: "hosts",
    tag: "hosts_dns"
  });

  const dnsRules = [
    { server: "hosts_dns", ip_accept_any: true },
    { server: "remote_dns", clash_mode: "Global" }
  ];
  if (hasDirectResolver) dnsRules.push({ server: "direct_dns", clash_mode: "Direct" });
  dnsRules.push({ action: "predefined", rcode: "NOERROR", query_type: [64, 65] });
  if (hasBypass) {
    dnsRules.push({ server: hasDirectResolver ? "direct_dns" : "remote_dns", ...bypassFields });
  }
  if (hasBypassApps) {
    dnsRules.push({ server: hasDirectResolver ? "direct_dns" : "remote_dns", process_name: bypassApps.processNames });
  }
  if (opts.useGeositePrivate) {
    dnsRules.push({ server: hasDirectResolver ? "direct_dns" : "remote_dns", rule_set: ["geosite-private"] });
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

  const selfPaths = opts.selfProcessPaths && opts.selfProcessPaths.length ? opts.selfProcessPaths : [];

  const routeRules = [];
  if (selfPaths.length) {
    // Evaluated first and by process identity, not sniffed domain — no need
    // to wait for the sniff action below. Extra safety alongside
    // auto_detect_interface, based on a real-world v2rayN Linux config.
    routeRules.push({ port: [53], process_path: selfPaths, action: "hijack-dns" });
    routeRules.push({ outbound: "direct", process_path: selfPaths });
  }
  routeRules.push(
    { action: "sniff" },
    {
      type: "logical", mode: "or",
      rules: [{ port: [53] }, { protocol: ["dns"] }],
      action: "hijack-dns"
    },
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

  const route = {
    default_domain_resolver: { server: hasDirectResolver ? "direct_dns" : "remote_dns" },
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
  remoteDns: document.getElementById("optRemoteDns"),
  remoteDnsCustom: document.getElementById("optRemoteDnsCustom"),
  localDns: document.getElementById("optLocalDns"),
  localDnsCustom: document.getElementById("optLocalDnsCustom"),
  localDohProvider: document.getElementById("optLocalDohProvider"),
  localDohProviderCustom: document.getElementById("optLocalDohProviderCustom"),
  blockQuic: document.getElementById("optBlockQuic"),
  blockIpv6: document.getElementById("optBlockIpv6"),
  tunAddr: document.getElementById("optTunAddr"),
  tunStack: document.getElementById("optTunStack"),
  strictRoute: document.getElementById("optStrictRoute"),
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
  selfProcessPaths: document.getElementById("optSelfProcessPaths"),
};

// Each page (index.html / linux.html) locks its platform via a hidden
// <select> with a single <option>. Both pages share the same localStorage
// (same origin), so a settings snapshot saved from the other page could
// otherwise try to restore a "platform" value with no matching <option> on
// this page — which the HTML spec says clears the selection rather than
// leaving it unchanged. Capturing the true value now, before restore can
// touch it, means this page's platform is never in question.
const PAGE_FIXED_PLATFORM = optionEls.platform.value;

// ============================================================
// PLATFORM PROFILE ISOLATION
// Each platform gets its own independent copy of the fields whose content
// is shaped for one OS and wrong-shaped for the other. Switching platforms
// swaps between two separate stashes rather than leaving stale content
// (Windows .exe names while Linux is selected, etc.) sitting in the field.
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
// ============================================================
const SETTINGS_STORAGE_KEY = "configforge:options:v1";

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
    // This page's platform is fixed — never trust a restored value for it
    // (see PAGE_FIXED_PLATFORM above for why).
    setOptionValue(optionEls.platform, PAGE_FIXED_PLATFORM);
    // Isolated fields are authoritatively owned by the profile store, not
    // the flat snapshot above — load from the profile for whichever
    // platform this page targets, so the two stay consistent.
    currentPlatformTracker = PAGE_FIXED_PLATFORM;
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
  // Only reset THIS page's own platform profile. Both pages share the same
  // localStorage (same origin) — wiping the whole entry or resetting both
  // profiles here would silently delete the other page's stashed settings
  // too, which is exactly the cross-page clash isolation is meant to avoid.
  platformProfiles[PAGE_FIXED_PLATFORM] = { ...PLATFORM_DEFAULTS[PAGE_FIXED_PLATFORM] };
  currentPlatformTracker = PAGE_FIXED_PLATFORM;
  applyConditionalVisibility();
  applyPlatformDefaults();
  regenerate();
  saveSettings(); // persists the reset state while preserving the other page's profile
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
  optionEls.localDnsCustom.hidden = optionEls.localDns.value !== "custom";
  const isDoh = optionEls.localDns.value === "doh";
  document.getElementById("localDohProviderRow").hidden = !isDoh;
  optionEls.localDohProviderCustom.hidden = !(isDoh && optionEls.localDohProvider.value === "custom");
  const geositeOn = optionEls.useGeositePrivate.checked;
  document.getElementById("ruleSetModeRow").hidden = !geositeOn;
  optionEls.ruleSetPath.hidden = !geositeOn || optionEls.ruleSetMode.value !== "local";
  document.getElementById("socksPortRow").style.opacity = optionEls.socksEnable.checked ? "1" : "0.4";
  const clashOn = optionEls.clashApi.checked;
  document.getElementById("clashPortRow").style.opacity = clashOn ? "1" : "0.4";
  document.getElementById("clashSecretRow").style.opacity = clashOn ? "1" : "0.4";
}

// Updates copy that differs by target OS. Isolated-field values themselves
// (ruleSetPath, bypassApps, selfProcessPaths) are handled by
// switchPlatformProfile(), not here — this only updates text/labels.
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
    localDns: optionEls.localDns.value,
    localDnsCustom: optionEls.localDnsCustom.value.trim(),
    localDohProvider: optionEls.localDohProvider.value,
    localDohProviderCustom: optionEls.localDohProviderCustom.value.trim(),
    blockQuic: optionEls.blockQuic.checked,
    blockIpv6: optionEls.blockIpv6.checked,
    tunName: FIXED_TUN_NAME,
    tunAddr: optionEls.tunAddr.value.trim() || "172.18.0.1/30",
    tunMtu: FIXED_TUN_MTU,
    tunStack: optionEls.tunStack.value,
    strictRoute: optionEls.strictRoute.checked,
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
optionEls.localDns.addEventListener("change", applyConditionalVisibility);
optionEls.localDohProvider.addEventListener("change", applyConditionalVisibility);
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
  if (opts.localDns === "custom" && !opts.localDnsCustom) {
    allWarnings.push("Local resolver is set to \"Custom IP…\" but the field is empty — direct/bypass domains will fall back to resolving via the tunneled DoH server instead, which can deadlock for a domain-based proxy server. Set an IP or switch to System default.");
  }
  const bypass = parseBypassDomains(optionEls.bypassDomains.value);
  bypass.warnings.forEach(w => allWarnings.push(w));
  opts.bypass = bypass;
  const bypassApps = parseBypassApps(optionEls.bypassApps.value, optionEls.platform.value);
  bypassApps.warnings.forEach(w => allWarnings.push(w));
  opts.bypassApps = bypassApps;
  const selfProcess = parseSelfProcessPaths(optionEls.selfProcessPaths.value, optionEls.platform.value);
  selfProcess.warnings.forEach(w => allWarnings.push(w));
  opts.selfProcessPaths = selfProcess.paths;
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
