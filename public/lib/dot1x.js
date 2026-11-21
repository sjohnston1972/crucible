/* 802.1X for Catalyst 9000 (IOS-XE 16+): settings, what a config already has,
 * which ports qualify, the config to add in either style, and the merge into
 * an existing config. Pure — browser- and Node-importable.
 *
 * Two styles, never mixed on one switch:
 *   classic — per-port `authentication …` commands
 *   policy  — IBNS 2.0: `access-session …` + a control policy-map on each port
 *
 * Existing config is matched by what it does, not by name: a RADIUS server at
 * the same IP under another name counts as present and its name is reused. A
 * single-value setting that is already set differently is reported and never
 * emitted, because pasting it would overwrite what is there.
 */

import { parse, normalizeInterfaceName } from "./parser.js";

export const POLICY_NAME = "DOT1X-MAB-POLICY";
export const PREAUTH_ACL = "ACL-PREAUTH";
export const IPDT_POLICY = "DOT1X-IPDT";
const CRITICAL_TEMPLATE = "CRITICAL_AUTH_ACCESS";
const CRITICAL_VOICE_TEMPLATE = "DEFAULT_CRITICAL_VOICE_TEMPLATE";

export const STYLE_LABEL = { policy: "Policy-based (IBNS 2.0)", classic: "Classic (per-port authentication commands)" };
export const MODE_LABEL = { monitor: "Monitor", low: "Low impact", closed: "Closed" };

// ------------------------------------------------------------------ settings

export const DOT1X_DEFAULTS = Object.freeze({
  style: "policy", // "policy" | "classic"
  server1Name: "ISE-1",
  server1Ip: "",
  server2Name: "ISE-2",
  server2Ip: "",
  key: "",
  authPort: 1812,
  acctPort: 1813,
  group: "ISE-RADIUS",
  sourceInterface: "",
  coa: true,
  coaKey: "", // blank = reuse the shared key
  mode: "monitor", // "monitor" | "low" | "closed"
  order: "dot1x", // "dot1x" (802.1X then MAB) | "mab" (MAB then 802.1X)
  hostMode: "multi-auth",
  txPeriod: 10,
  reauth: true,
  criticalVlan: "",
  criticalVoice: true,
  probeUser: "",
  skipWords: "", // comma-separated; ports whose description contains one are left alone
});

const HOST_MODES = ["multi-auth", "multi-domain", "multi-host", "single-host"];
const str = (v) => String(v == null ? "" : v).trim();
const pick = (v, allowed, fallback) => (allowed.includes(v) ? v : fallback);
const num = (v, fallback) => (str(v) === "" ? fallback : Number(v));

export function normalizeSettings(raw = {}) {
  const d = DOT1X_DEFAULTS;
  const r = { ...d, ...raw };
  return {
    style: pick(r.style, ["policy", "classic"], d.style),
    server1Name: str(r.server1Name),
    server1Ip: str(r.server1Ip),
    server2Name: str(r.server2Name),
    server2Ip: str(r.server2Ip),
    key: str(r.key),
    authPort: num(r.authPort, d.authPort),
    acctPort: num(r.acctPort, d.acctPort),
    group: str(r.group),
    sourceInterface: str(r.sourceInterface),
    coa: !!r.coa,
    coaKey: str(r.coaKey),
    mode: pick(r.mode, ["monitor", "low", "closed"], d.mode),
    order: pick(r.order, ["dot1x", "mab"], d.order),
    hostMode: pick(r.hostMode, HOST_MODES, d.hostMode),
    txPeriod: num(r.txPeriod, d.txPeriod),
    reauth: !!r.reauth,
    criticalVlan: str(r.criticalVlan),
    criticalVoice: !!r.criticalVoice,
    probeUser: str(r.probeUser),
    skipWords: str(r.skipWords),
  };
}

const isIpv4 = (s) => {
  const m = String(s).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
};
const isPort = (n) => Number.isInteger(n) && n >= 1 && n <= 65535;
const isWord = (s) => /^\S+$/.test(s);

/** Problems that stop generation, each naming the box to fix. Empty = good to go. */
export function validateSettings(raw) {
  const s = normalizeSettings(raw);
  const out = [];
  if (!s.server1Name) out.push("RADIUS server 1 name is blank.");
  else if (!isWord(s.server1Name)) out.push("RADIUS server 1 name must not contain spaces.");
  if (!s.server1Ip) out.push("RADIUS server 1 IP is blank.");
  else if (!isIpv4(s.server1Ip)) out.push(`RADIUS server 1 IP "${s.server1Ip}" is not an IPv4 address.`);
  if (s.server2Ip) {
    if (!isIpv4(s.server2Ip)) out.push(`RADIUS server 2 IP "${s.server2Ip}" is not an IPv4 address.`);
    if (!s.server2Name) out.push("RADIUS server 2 name is blank.");
    else if (!isWord(s.server2Name)) out.push("RADIUS server 2 name must not contain spaces.");
    if (s.server2Ip === s.server1Ip) out.push("RADIUS server 2 IP is the same as server 1.");
    if (s.server2Name && s.server2Name === s.server1Name) out.push("RADIUS server 2 name is the same as server 1.");
  }
  if (!s.key) out.push("Shared key is blank.");
  else if (/\s/.test(s.key)) out.push("Shared key must not contain spaces.");
  if (/\s/.test(s.coaKey)) out.push("CoA key must not contain spaces.");
  if (!isPort(s.authPort)) out.push("Auth port must be a number from 1 to 65535.");
  if (!isPort(s.acctPort)) out.push("Accounting port must be a number from 1 to 65535.");
  if (!s.group) out.push("Server group name is blank.");
  else if (!isWord(s.group)) out.push("Server group name must not contain spaces.");
  if (!Number.isInteger(s.txPeriod) || s.txPeriod < 1 || s.txPeriod > 65535) out.push("802.1X tx-period must be a number from 1 to 65535.");
  if (s.criticalVlan && !(/^\d+$/.test(s.criticalVlan) && Number(s.criticalVlan) >= 1 && Number(s.criticalVlan) <= 4094)) {
    out.push("Critical VLAN must be a number from 1 to 4094.");
  }
  if (s.probeUser && !isWord(s.probeUser)) out.push("Server probe username must not contain spaces.");
  return out;
}

const serversOf = (s) =>
  [
    { name: s.server1Name, ip: s.server1Ip },
    { name: s.server2Name, ip: s.server2Ip },
  ].filter((x) => x.ip);

// ---------------------------------------------------------------------- scan

const isIndented = (l) => /^[ \t]/.test(l);

/** Top-level commands, each with its indented child lines (trimmed, `!` dropped). */
function topBlocks(lines) {
  const out = [];
  let cur = null;
  for (const raw of lines || []) {
    const t = raw.trim();
    if (t === "") continue;
    if (isIndented(raw)) {
      if (cur && t !== "!") cur.children.push(t);
      continue;
    }
    cur = t === "!" ? null : { head: t, children: [] };
    if (cur) out.push(cur);
  }
  return out;
}

const PORT_STYLE_CLASSIC = /^authentication port-control\b/;
const PORT_STYLE_POLICY = /^(access-session port-control\b|service-policy type control subscriber\b)/;
const ifaceChildren = (f) => (f.block || []).slice(1).map((l) => l.trim()).filter((l) => l && l !== "!");

/**
 * What 802.1X-related config a parsed config already carries.
 * `supported` is false for a `version` below 16 (not a Catalyst 9000 / IOS-XE).
 * `style` is the style its ports already use, or null when none do.
 */
export function scanDot1x(parsed) {
  const blocks = topBlocks(parsed.lines);
  const scan = {
    version: null,
    supported: true,
    aaaNewModel: false,
    servers: [], // { name, ip, authPort, acctPort }
    groups: [], // { name, servers: [names], sourceInterface }
    top: [], // every top-level line
    coaClients: [],
    hasCoaBlock: false,
    systemAuthControl: false,
    dtPolicies: new Set(),
    acls: new Set(),
    policyMaps: new Set(),
    classMaps: new Set(),
    serviceTemplates: new Set(),
    style: null,
  };
  let m;
  for (const b of blocks) {
    const h = b.head;
    scan.top.push(h);
    if (scan.version === null && (m = h.match(/^version\s+(\d+)\.(\d+)/))) {
      scan.version = `${m[1]}.${m[2]}`;
      scan.supported = Number(m[1]) >= 16;
    } else if (/^aaa new-model\b/.test(h)) scan.aaaNewModel = true;
    else if ((m = h.match(/^radius server\s+(\S+)/))) {
      const srv = { name: m[1], ip: null, authPort: null, acctPort: null };
      for (const c of b.children) {
        const a = c.match(/^address ipv4\s+(\S+)(?:\s+auth-port\s+(\d+))?(?:\s+acct-port\s+(\d+))?/);
        if (a) Object.assign(srv, { ip: a[1], authPort: a[2] ? Number(a[2]) : null, acctPort: a[3] ? Number(a[3]) : null });
      }
      scan.servers.push(srv);
    } else if ((m = h.match(/^aaa group server radius\s+(\S+)/))) {
      // The same group header can appear twice in a file; it is one group.
      let g = scan.groups.find((x) => x.name === m[1]);
      if (!g) scan.groups.push((g = { name: m[1], servers: [], sourceInterface: null }));
      for (const c of b.children) {
        let k;
        if ((k = c.match(/^server name\s+(\S+)/))) g.servers.push(k[1]);
        else if ((k = c.match(/^ip radius source-interface\s+(\S+)/))) g.sourceInterface = k[1];
      }
    } else if (/^aaa server radius dynamic-author\b/.test(h)) {
      scan.hasCoaBlock = true;
      for (const c of b.children) {
        const k = c.match(/^client\s+(\S+)/);
        if (k) scan.coaClients.push(k[1]);
      }
    } else if (/^dot1x system-auth-control\b/.test(h)) scan.systemAuthControl = true;
    else if ((m = h.match(/^device-tracking policy\s+(\S+)/))) scan.dtPolicies.add(m[1]);
    else if ((m = h.match(/^ip access-list extended\s+(\S+)/))) scan.acls.add(m[1]);
    else if ((m = h.match(/^policy-map type control subscriber\s+(\S+)/))) scan.policyMaps.add(m[1]);
    else if ((m = h.match(/^class-map type control subscriber\s+\S+\s+(\S+)/))) scan.classMaps.add(m[1]);
    else if ((m = h.match(/^service-template\s+(\S+)/))) scan.serviceTemplates.add(m[1]);
  }
  for (const f of parsed.interfaces || []) {
    const kids = ifaceChildren(f);
    if (kids.some((c) => PORT_STYLE_POLICY.test(c))) {
      scan.style = "policy";
      break;
    }
    if (kids.some((c) => PORT_STYLE_CLASSIC.test(c))) scan.style = "classic";
  }
  return scan;
}

// --------------------------------------------------------------------- ports

const PHYSICAL_RE = /^(FastEthernet|GigabitEthernet|TwoGigabitEthernet|FiveGigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|Ethernet)\d/;

const skipList = (s) =>
  str(s.skipWords)
    .split(",")
    .map((w) => w.trim().toLowerCase())
    .filter(Boolean);

/**
 * The access ports 802.1X applies to: physical Ethernet, access mode (or an
 * access VLAN and not a trunk), not a port-channel member, no IP address.
 * Ports whose description contains a skip word are returned in `skipped`.
 */
export function qualifyingPorts(parsed, settings) {
  const words = skipList(normalizeSettings(settings));
  const ports = [];
  const skipped = [];
  for (const f of parsed.interfaces || []) {
    if (!PHYSICAL_RE.test(f.normName)) continue;
    if (f.channelGroup != null || f.hasIp) continue;
    const sw = f.switchportLines || [];
    const trunk = sw.some((l) => /^switchport mode (trunk|dynamic)/.test(l));
    const access = sw.some((l) => /^switchport mode access\b/.test(l)) || (!trunk && sw.some((l) => /^switchport access vlan\b/.test(l)));
    if (!access || sw.some((l) => /^no switchport\b/.test(l))) continue;
    const desc = (f.description || "").toLowerCase();
    const word = words.find((w) => desc.includes(w));
    if (word) skipped.push({ name: f.name, normName: f.normName, description: f.description, word });
    else ports.push({ name: f.name, normName: f.normName, description: f.description, iface: f });
  }
  return { ports, skipped };
}

// ---------------------------------------------------------------- generators

const EMPTY_SCAN = () => scanDot1x({ lines: [], interfaces: [] });

function radiusServerBlock(s, srv) {
  const lines = [`radius server ${srv.name}`, ` address ipv4 ${srv.ip} auth-port ${s.authPort} acct-port ${s.acctPort}`, ` key ${s.key}`];
  if (s.probeUser) lines.push(` automate-tester username ${s.probeUser} ignore-acct-port probe-on`);
  return lines;
}

const RADIUS_ATTRIBUTES = [
  "radius-server attribute 6 on-for-login-auth",
  "radius-server attribute 8 include-in-access-req",
  "radius-server attribute 25 access-request include",
  "radius-server attribute 31 mac format ietf upper-case",
  "radius-server attribute 31 send nas-port-detail mac-only",
];
const RADIUS_DEAD = [
  { line: "aaa accounting update newinfo periodic 2880", key: /^aaa accounting update\b/ },
  { line: "radius-server dead-criteria time 10 tries 3", key: /^radius-server dead-criteria\b/ },
  { line: "radius-server deadtime 15", key: /^radius-server deadtime\b/ },
];

const PREAUTH_ACL_LINES = [
  `ip access-list extended ${PREAUTH_ACL}`,
  " permit udp any eq bootpc any eq bootps",
  " permit udp any any eq domain",
  " deny ip any any",
];

/** Class-maps, service-template and the control policy-map for the policy-based style. */
function controlPolicyLines(s, scan) {
  const critical = !!s.criticalVlan;
  const out = [];
  if (critical && !scan.serviceTemplates.has(CRITICAL_TEMPLATE)) {
    out.push(`service-template ${CRITICAL_TEMPLATE}`, ` vlan ${s.criticalVlan}`, "!");
  }
  if (critical && s.criticalVoice && !scan.serviceTemplates.has(CRITICAL_VOICE_TEMPLATE)) {
    out.push(`service-template ${CRITICAL_VOICE_TEMPLATE}`, " voice vlan", "!");
  }
  const cmap = (name, match, body) => {
    if (scan.classMaps.has(name)) return;
    out.push(`class-map type control subscriber ${match} ${name}`, ...body.map((l) => " " + l), "!");
  };
  const criticalTemplates = [CRITICAL_TEMPLATE, ...(s.criticalVoice ? [CRITICAL_VOICE_TEMPLATE] : [])];
  if (critical) {
    cmap("AAA_SVR_DOWN_UNAUTHD_HOST", "match-all", ["match result-type aaa-timeout", "match authorization-status unauthorized"]);
  }
  cmap("AAA_SVR_DOWN_AUTHD_HOST", "match-all", ["match result-type aaa-timeout", "match authorization-status authorized"]);
  cmap("DOT1X_FAILED", "match-all", ["match method dot1x", "match result-type method dot1x authoritative"]);
  cmap("DOT1X_NO_RESP", "match-all", ["match method dot1x", "match result-type method dot1x agent-not-found"]);
  cmap("MAB_FAILED", "match-all", ["match method mab", "match result-type method mab authoritative"]);
  if (critical) {
    const m = criticalTemplates.map((t) => `match activated-service-template ${t}`);
    cmap("IN_CRITICAL_AUTH", "match-any", m);
    cmap("NOT_IN_CRITICAL_AUTH", "match-none", m);
  }

  const p = [`policy-map type control subscriber ${POLICY_NAME}`];
  const event = (name, how) => p.push(` event ${name} ${how}`);
  const cls = (n, name, actions) => {
    p.push(`  ${n} class ${name} do-until-failure`);
    actions.forEach((a, i) => p.push(`   ${(i + 1) * 10} ${a}`));
  };
  const DOT1X = "authenticate using dot1x priority 10";
  const MAB = "authenticate using mab priority 20";
  const dot1xFirst = s.order === "dot1x";

  event("session-started", "match-all");
  cls(10, "always", [dot1xFirst ? DOT1X : MAB]);

  event("authentication-failure", "match-first");
  if (dot1xFirst) cls(5, "DOT1X_FAILED", ["terminate dot1x", MAB]);
  else cls(5, "MAB_FAILED", ["terminate mab", DOT1X]);
  if (critical) {
    cls(10, "AAA_SVR_DOWN_UNAUTHD_HOST", [
      "clear-authenticated-data-hosts-on-port",
      ...criticalTemplates.map((t) => `activate service-template ${t}`),
      "authorize",
      "pause reauthentication",
    ]);
  }
  cls(20, "AAA_SVR_DOWN_AUTHD_HOST", ["pause reauthentication", "authorize"]);
  if (dot1xFirst) {
    cls(30, "DOT1X_NO_RESP", ["terminate dot1x", MAB]);
    cls(40, "MAB_FAILED", ["terminate mab", "authentication-restart 60"]);
  } else {
    cls(30, "DOT1X_FAILED", ["terminate dot1x", "authentication-restart 60"]);
    cls(40, "DOT1X_NO_RESP", ["terminate dot1x", "authentication-restart 60"]);
  }
  cls(60, "always", ["terminate dot1x", "terminate mab", "authentication-restart 60"]);

  event("aaa-available", "match-all");
  if (critical) {
    cls(10, "IN_CRITICAL_AUTH", ["clear-session"]);
    cls(20, "NOT_IN_CRITICAL_AUTH", ["resume reauthentication"]);
  } else {
    cls(10, "always", ["resume reauthentication"]);
  }

  event("agent-found", "match-all");
  cls(10, "always", ["terminate mab", DOT1X]);

  event("inactivity-timeout", "match-all");
  cls(10, "always", ["clear-session"]);

  return [...out, ...p];
}

/**
 * The global config as check items. `need` says whether any port will take the
 * device-tracking policy / control policy (no point defining one nothing uses).
 */
function globalItems(s, scan, need) {
  const items = [];
  const names = { servers: [], group: s.group };
  const add = (id, label, state, detail = "", lines = []) =>
    items.push({ id, label, state, detail, lines: state === "missing" ? lines : [] });
  const has = (line) => scan.top.includes(line);

  // AAA
  add(
    "aaa",
    "aaa new-model",
    scan.aaaNewModel ? "present" : "missing",
    scan.aaaNewModel ? "" : "Changes how administrators log in — confirm a local user or TACACS login works before pasting.",
    ["aaa new-model"]
  );

  // RADIUS servers — matched by IP, the existing name is reused
  for (const srv of serversOf(s)) {
    const byIp = scan.servers.find((x) => x.ip === srv.ip);
    const byName = scan.servers.find((x) => x.name === srv.name);
    const label = `RADIUS server ${srv.ip}`;
    if (byIp) {
      names.servers.push(byIp.name);
      const portsDiffer =
        (byIp.authPort != null && byIp.authPort !== s.authPort) || (byIp.acctPort != null && byIp.acctPort !== s.acctPort);
      if (portsDiffer) {
        add(`server:${srv.ip}`, label, "differs", `"${byIp.name}" uses ports ${byIp.authPort}/${byIp.acctPort}, settings say ${s.authPort}/${s.acctPort}.`);
      } else {
        add(`server:${srv.ip}`, label, "present", byIp.name !== srv.name ? `defined as "${byIp.name}" — that name is reused.` : "");
      }
    } else if (byName) {
      names.servers.push(byName.name);
      add(`server:${srv.ip}`, label, "differs", `radius server ${byName.name} is ${byName.ip || "(no address)"}, settings say ${srv.ip}.`);
    } else {
      names.servers.push(srv.name);
      add(`server:${srv.ip}`, label, "missing", "", radiusServerBlock(s, srv));
    }
  }

  // Server group — matched by its members
  const want = names.servers;
  const g =
    scan.groups.find((x) => want.every((n) => x.servers.includes(n))) ||
    scan.groups.find((x) => x.name === s.group) ||
    scan.groups.find((x) => want.some((n) => x.servers.includes(n)));
  if (g) names.group = g.name;
  const groupLines = [];
  const missingMembers = g ? want.filter((n) => !g.servers.includes(n)) : want;
  groupLines.push(...missingMembers.map((n) => ` server name ${n}`));
  const sameIface = (a, b) => normalizeInterfaceName(a).toLowerCase() === normalizeInterfaceName(b).toLowerCase();
  let ifaceDiffers = null;
  if (s.sourceInterface) {
    if (!g || !g.sourceInterface) groupLines.push(` ip radius source-interface ${s.sourceInterface}`);
    else if (!sameIface(g.sourceInterface, s.sourceInterface)) ifaceDiffers = g.sourceInterface;
  }
  if (groupLines.length) {
    add(
      "group",
      `RADIUS server group ${names.group}`,
      "missing",
      g ? `exists — ${groupLines.length} line${groupLines.length === 1 ? "" : "s"} to add.` : "",
      [`aaa group server radius ${names.group}`, ...groupLines]
    );
  } else {
    add("group", `RADIUS server group ${names.group}`, "present", g && g.name !== s.group ? `that name is reused (settings say "${s.group}").` : "");
  }
  if (ifaceDiffers) {
    add("group-source", "RADIUS source interface", "differs", `group ${names.group} uses ${ifaceDiffers}, settings say ${s.sourceInterface}.`);
  }

  // Method lists
  const method = (id, label, re, line) => {
    const existing = scan.top.find((l) => re.test(l));
    if (!existing) return add(id, label, "missing", "", [line]);
    if (new RegExp(`\\bgroup ${names.group.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\s|$)`).test(existing)) return add(id, label, "present");
    add(id, label, "differs", `is "${existing}", settings would use group ${names.group}.`);
  };
  method("authn", "aaa authentication dot1x", /^aaa authentication dot1x default\b/, `aaa authentication dot1x default group ${names.group}`);
  method("authz", "aaa authorization network", /^aaa authorization network default\b/, `aaa authorization network default group ${names.group}`);
  // New-style switches show accounting as `aaa accounting Identity`; either form does the job there.
  if (s.style === "policy") {
    method("acct", "aaa accounting identity", /^aaa accounting (identity|dot1x) default\b/i, `aaa accounting identity default start-stop group ${names.group}`);
  } else {
    method("acct", "aaa accounting dot1x", /^aaa accounting dot1x default\b/, `aaa accounting dot1x default start-stop group ${names.group}`);
  }

  // Change of authorisation
  if (s.coa) {
    const coaKey = s.coaKey || s.key;
    const missing = serversOf(s).filter((x) => !scan.coaClients.includes(x.ip));
    add(
      "coa",
      "CoA (dynamic authorisation) clients",
      missing.length ? "missing" : "present",
      missing.length ? missing.map((x) => x.ip).join(", ") : "",
      ["aaa server radius dynamic-author", ...missing.map((x) => ` client ${x.ip} server-key ${coaKey}`)]
    );
  }

  // RADIUS attributes and dead-server detection
  const attrMissing = RADIUS_ATTRIBUTES.filter((l) => !has(l));
  for (const d of RADIUS_DEAD) {
    const existing = scan.top.find((l) => d.key.test(l));
    if (!existing) attrMissing.push(d.line);
    else if (existing !== d.line) add(`dead:${d.line}`, d.line.replace(/\s+\d.*$/, ""), "differs", `is "${existing}", settings would use "${d.line}".`);
  }
  add(
    "radius-attrs",
    "RADIUS attributes and dead-server detection",
    attrMissing.length ? "missing" : "present",
    attrMissing.length ? `${attrMissing.length} line${attrMissing.length === 1 ? "" : "s"} to add.` : "",
    attrMissing
  );

  add("sysauth", "dot1x system-auth-control", scan.systemAuthControl ? "present" : "missing", "", ["dot1x system-auth-control"]);

  if (need.ipdt) {
    add("ipdt", `device-tracking policy ${IPDT_POLICY}`, scan.dtPolicies.has(IPDT_POLICY) ? "present" : "missing", "", [
      `device-tracking policy ${IPDT_POLICY}`,
      " no protocol udp",
      " tracking enable",
    ]);
  }
  if (s.mode === "low") {
    add("preauth-acl", `pre-auth ACL ${PREAUTH_ACL}`, scan.acls.has(PREAUTH_ACL) ? "present" : "missing", "", PREAUTH_ACL_LINES);
  }
  if (s.style === "policy" && need.policy) {
    add(
      "policy",
      `control policy ${POLICY_NAME}`,
      scan.policyMaps.has(POLICY_NAME) ? "present" : "missing",
      "",
      controlPolicyLines(s, scan)
    );
  }
  return items;
}

/** Join item blocks with `!` separators. */
function joinBlocks(blocks) {
  const out = [];
  for (const b of blocks) {
    if (!b.length) continue;
    if (out.length) out.push("!");
    out.push(...(b[b.length - 1] === "!" ? b.slice(0, -1) : b));
  }
  return out;
}

/** The whole global block for a switch with no 802.1X at all. */
export function globalLines(settings) {
  const s = normalizeSettings(settings);
  return joinBlocks(globalItems(s, EMPTY_SCAN(), { ipdt: true, policy: true }).map((i) => i.lines));
}

/**
 * The lines one port should carry, in order. `key` finds an existing line that
 * sets the same thing; `single` means only one value can exist, so a different
 * existing value is reported instead of overwritten.
 */
function wantedPortLines(s) {
  const w = [];
  const one = (line, key) => w.push({ line, key, single: true });
  const flag = (line) => w.push({ line, key: null, single: false });
  const classic = s.style === "classic";
  const order = s.order === "dot1x" ? "dot1x mab" : "mab dot1x";

  if (classic) {
    w.push({ line: `authentication host-mode ${s.hostMode}`, key: /^authentication host-mode\b/, single: true, role: "host" });
    one(`authentication order ${order}`, /^authentication order\b/);
    one("authentication priority dot1x mab", /^authentication priority\b/);
    one("authentication port-control auto", /^authentication port-control\b/);
  } else {
    w.push({ line: `access-session host-mode ${s.hostMode}`, key: /^access-session host-mode\b/, single: true, role: "host" });
    one("access-session port-control auto", /^access-session port-control\b/);
  }
  if (s.reauth) {
    flag("authentication periodic");
    one("authentication timer reauthenticate server", /^authentication timer reauthenticate\b/);
  }
  if (classic && s.criticalVlan) {
    one(`authentication event server dead action authorize vlan ${s.criticalVlan}`, /^authentication event server dead action (authorize|reinitialize) vlan\b/);
    if (s.criticalVoice) flag("authentication event server dead action authorize voice");
    one("authentication event server alive action reinitialize", /^authentication event server alive action\b/);
  }
  flag("mab");
  flag("dot1x pae authenticator");
  one(`dot1x timeout tx-period ${s.txPeriod}`, /^dot1x timeout tx-period\b/);
  if (s.mode === "low") one(`ip access-group ${PREAUTH_ACL} in`, /^ip access-group \S+ in\b/);
  one(`device-tracking attach-policy ${IPDT_POLICY}`, /^device-tracking attach-policy\b/);
  if (!classic) one(`service-policy type control subscriber ${POLICY_NAME}`, /^service-policy type control subscriber\b/);
  return w;
}

/** The whole port block for a port with no 802.1X at all. */
export function portLines(settings) {
  const s = normalizeSettings(settings);
  return checkPort({ block: ["interface x"] }, s).add;
}

const DEFAULT_HOST_MODE = { classic: "single-host", policy: "multi-auth" };

/** Compare one interface with the wanted lines. Returns { add, remove, differs, configured, closing }. */
function checkPort(iface, s) {
  const have = ifaceChildren(iface);
  const classic = s.style === "classic";
  const configured = have.some((c) => (classic ? PORT_STYLE_CLASSIC : /^access-session port-control\b/).test(c));
  const add = [];
  const remove = [];
  const differs = [];

  for (const w of wantedPortLines(s)) {
    if (have.includes(w.line)) continue;
    const existing = w.key ? have.find((c) => w.key.test(c)) : null;
    if (existing) {
      differs.push(`has "${existing}", settings say "${w.line}"`);
      continue;
    }
    // A port already running 802.1X with no host-mode line is on the default.
    if (w.role === "host" && configured) {
      const dflt = DEFAULT_HOST_MODE[s.style];
      if (s.hostMode !== dflt) differs.push(`host mode is the default (${dflt}), settings say "${s.hostMode}"`);
      continue;
    }
    add.push(w.line);
  }

  // Open / closed. A port that is already closed is never opened.
  let closing = false;
  const openLine = "authentication open";
  const closedLine = "access-session closed";
  const place = (line, after) => {
    const at = add.findIndex((l) => after.test(l));
    add.splice(at < 0 ? add.length : at + 1, 0, line);
  };
  if (classic) {
    const open = have.includes(openLine);
    if (s.mode === "closed") {
      if (open) {
        remove.push(openLine);
        closing = true;
      }
    } else if (!open) {
      if (configured) differs.push(`port is in closed mode — left closed (settings say ${MODE_LABEL[s.mode]})`);
      else place(openLine, /^authentication port-control\b/);
    }
  } else {
    const closed = have.includes(closedLine);
    if (s.mode === "closed") {
      if (!closed) {
        place(closedLine, /^access-session host-mode\b/);
        closing = configured;
      }
    } else if (closed) {
      differs.push(`port is in closed mode — left closed (settings say ${MODE_LABEL[s.mode]})`);
    }
  }
  return { add, remove, differs, configured, closing };
}

// --------------------------------------------------------------------- check

/**
 * Check a parsed config against the settings.
 *   opts.ports         — Set of normNames to include (null = every qualifying port)
 *   opts.ignoreVersion — skip the Catalyst 9000 version guard (main flow)
 * Item / port states: present | missing | differs | conflict (ports: done | partial | missing | conflict).
 */
export function checkDot1x(parsed, settings, opts = {}) {
  const s = normalizeSettings(settings);
  const scan = scanDot1x(parsed);
  const base = { supported: true, version: scan.version, style: scan.style, conflict: false, items: [], ports: [], skipped: [], global: [], warnings: [], complete: false };
  const counts = { globalsPresent: 0, globalsTotal: 0, portsDone: 0, portsTotal: 0 };
  if (!scan.supported && !opts.ignoreVersion) {
    return { ...base, supported: false, counts, warnings: [`IOS ${scan.version} is not a Catalyst 9000 — use the main flow at the top.`] };
  }

  const conflict = !!scan.style && scan.style !== s.style;
  const q = qualifyingPorts(parsed, s);
  const chosen = q.ports.filter((p) => !opts.ports || opts.ports.has(p.normName));
  const warnings = [];

  const ports = chosen.map((p) => {
    if (conflict) return { name: p.name, normName: p.normName, description: p.description, state: "conflict", add: [], remove: [], differs: [], closing: false };
    const r = checkPort(p.iface, s);
    const state = !r.add.length && !r.remove.length ? "done" : r.configured ? "partial" : "missing";
    return { name: p.name, normName: p.normName, description: p.description, state, add: r.add, remove: r.remove, differs: r.differs, closing: r.closing };
  });

  const attach = `device-tracking attach-policy ${IPDT_POLICY}`;
  const service = `service-policy type control subscriber ${POLICY_NAME}`;
  const need = {
    ipdt: ports.some((p) => p.add.includes(attach)),
    policy: !conflict && ports.some((p) => p.add.includes(service)),
  };
  const items = globalItems(s, scan, need);

  if (conflict) {
    warnings.push(
      `Ports already use the ${STYLE_LABEL[scan.style]} style but the settings select ${STYLE_LABEL[s.style]}. ` +
        `The two cannot be mixed, so no port lines were generated — only the global lines both styles share.`
    );
  }
  const aaa = items.find((i) => i.id === "aaa");
  if (aaa.state === "missing") warnings.push("aaa new-model is not enabled. Adding it changes how administrators log in — confirm a local user or TACACS login works before pasting.");
  const closing = ports.filter((p) => p.closing).length;
  if (closing) warnings.push(`${closing} port${closing === 1 ? "" : "s"} already running 802.1X in open mode will move to CLOSED mode.`);
  if (s.style === "policy" && s.order === "mab" && need.policy) {
    warnings.push("The MAB-first control policy is adapted from Cisco's 802.1X-first reference policy, not taken from a Cisco example - lab-test it before rollout.");
  }
  if (!q.ports.length) warnings.push("No access ports qualify for 802.1X on this switch.");

  counts.globalsTotal = items.length;
  counts.globalsPresent = items.filter((i) => i.state === "present").length;
  counts.portsTotal = ports.length;
  counts.portsDone = ports.filter((p) => p.state === "done").length;

  return {
    ...base,
    conflict,
    items,
    ports,
    skipped: q.skipped,
    global: joinBlocks(items.map((i) => i.lines)),
    warnings,
    counts,
    complete: !conflict && items.every((i) => i.state !== "missing") && ports.every((p) => p.state === "done"),
  };
}

// -------------------------------------------------------------- changes file

/**
 * The paste-ready changes file: `!` comments, then only the lines that are
 * missing. Ports that need the same lines share one stanza each (no ranges, so
 * every line is plain to read and to back out).
 */
export function changesText(check, { hostname = "", settings } = {}) {
  const s = normalizeSettings(settings);
  const out = [
    `! 802.1X changes for ${hostname || "(no hostname)"}`,
    `! Generated by Crucible - style: ${STYLE_LABEL[s.style]}, mode: ${MODE_LABEL[s.mode]}`,
  ];
  if (!check.supported) {
    out.push(...check.warnings.map((w) => `! ${w}`), "! No changes generated.");
    return out.join("\n") + "\n";
  }
  for (const w of check.warnings) out.push(`! WARNING: ${w}`);
  for (const i of check.items.filter((x) => x.state === "differs")) out.push(`! NOT CHANGED: ${i.label} - ${i.detail}`);
  for (const p of check.ports) for (const d of p.differs) out.push(`! NOT CHANGED: ${p.normName} - ${d}`);

  const portWork = check.ports.filter((p) => p.add.length || p.remove.length);
  if (!check.global.length && !portWork.length) {
    out.push("!", "! No changes needed.");
    return out.join("\n") + "\n";
  }
  if (check.global.length) out.push("!", ...check.global);
  for (const p of portWork) {
    out.push("!", `interface ${p.name}`, ...p.remove.map((l) => ` no ${l}`), ...p.add.map((l) => ` ${l}`));
  }
  out.push("!");
  return out.join("\n") + "\n";
}

// --------------------------------------------------------------------- merge

/**
 * Merge a check's changes into the config text it was run on, keeping
 * everything else as it is. Port lines go into each existing interface block;
 * the global lines go under a `! ==== 802.1X ====` header straight after the
 * `ip domain name` line (before the first interface when there is none), so
 * everything the ports reference is defined before them.
 * Returns { content, added }.
 */
export function applyDot1x(text, check) {
  const crlf = /\r\n/.test(String(text));
  const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  let added = 0;

  for (const p of check.ports || []) {
    if (!p.add.length && !p.remove.length) continue;
    const at = lines.findIndex((l) => {
      const m = l.match(/^interface\s+(\S+)/);
      return m && normalizeInterfaceName(m[1]) === p.normName;
    });
    if (at < 0) continue;
    let end = at;
    while (end + 1 < lines.length && isIndented(lines[end + 1]) && lines[end + 1].trim() !== "") end++;
    const kept = lines.slice(at + 1, end + 1).filter((l) => !p.remove.includes(l.trim()));
    const have = new Set(kept.map((l) => l.trim()));
    const fresh = p.add.filter((l) => !have.has(l)).map((l) => ` ${l}`);
    lines.splice(at + 1, end - at, ...kept, ...fresh);
    added += fresh.length;
  }

  if ((check.global || []).length) {
    const block = [...check.global];
    const domainIdx = lines.findIndex((l) => /^ip domain[- ]name\s+\S/.test(l));
    const firstIface = lines.findIndex((l) => /^interface\s+\S/.test(l));
    let at; // insert before this index
    if (domainIdx >= 0) at = domainIdx + 1;
    else if (firstIface >= 0) at = firstIface;
    else at = lines.length;
    // AAA commands are rejected ahead of `aaa new-model`; lead with it when the
    // file only enables it further down (the command is harmless to repeat).
    const aaaIdx = lines.findIndex((l) => /^aaa new-model\b/.test(l));
    if (aaaIdx >= at && block[0] !== "aaa new-model") block.unshift("aaa new-model", "!");
    const lead = at > 0 && lines[at - 1].trim() === "!" ? [] : ["!"];
    const tail = (lines[at] || "").trim() === "!" ? [] : ["!"];
    lines.splice(at, 0, ...lead, "! ==== 802.1X ====", ...block, ...tail);
    added += block.filter((l) => l !== "!").length;
  }

  const content = lines.join("\n");
  return { content: crlf ? content.replace(/\n/g, "\r\n") : content, added };
}

// ----------------------------------------------------------------- main flow

const PORT_DOT1X_RE = /^(authentication\s|dot1x\s|mab(\s|$)|access-session\s|service-policy type control subscriber\s)/;

/** Remove every per-port 802.1X line (either style). Returns { content, ports: [names] }. */
export function stripPortDot1x(text) {
  const crlf = /\r\n/.test(String(text));
  const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  const ports = [];
  const out = [];
  let current = null;
  for (const l of lines) {
    if (!isIndented(l)) {
      const m = l.match(/^interface\s+(\S+)/);
      current = m ? m[1] : null;
    } else if (current && PORT_DOT1X_RE.test(l.trim())) {
      if (!ports.includes(current)) ports.push(current);
      continue;
    }
    out.push(l);
  }
  const content = out.join("\n");
  return { content: crlf ? content.replace(/\n/g, "\r\n") : content, ports };
}

/**
 * Main flow: put 802.1X into a freshly generated switch config. The config is
 * for a new switch, so 802.1X port lines copied over from the old one are
 * replaced with the selected style rather than treated as a conflict.
 * Returns { content, warnings, ports } (ports = how many got the port block).
 */
export function addDot1xToOutput(text, settings) {
  const s = normalizeSettings(settings);
  const warnings = [];
  const stripped = stripPortDot1x(text);
  if (stripped.ports.length) {
    warnings.push(`replaced the old 802.1X lines on ${stripped.ports.length} port${stripped.ports.length === 1 ? "" : "s"} with the ${STYLE_LABEL[s.style]} style.`);
  }
  const check = checkDot1x(parse(stripped.content), s, { ignoreVersion: true });
  for (const w of check.warnings) if (!/^aaa new-model/.test(w)) warnings.push(w);
  for (const i of check.items.filter((x) => x.state === "differs")) warnings.push(`802.1X not changed: ${i.label} - ${i.detail}`);
  for (const p of check.ports) for (const d of p.differs) warnings.push(`802.1X not changed: ${p.normName} - ${d}`);
  const res = applyDot1x(stripped.content, check);
  return { content: res.content, warnings, ports: check.ports.filter((p) => p.add.length).length };
}
