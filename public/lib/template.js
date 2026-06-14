/* Template engine: tag map, block extraction, tag/direct insertion, naming.
 * Pure, browser- and Node-importable.
 *
 * Tag model (refinement of spec §5): every selected INTERFACE gets its own
 * sequential tag (interfaces are identical across all sites, so the map is
 * stable). Each variable-size category (static routes, routing protocols,
 * VRFs, spanning-tree, DHCP) gets ONE stable category tag, so a single shared
 * template has a fixed, predictable marker set across every site. Hardening
 * uses the named {harden} marker.
 */

import { normalizeInterfaceName } from "./parser.js";

// ------------------------------------------------------------- tag sequencing

/** 0-based index → bijective base-26 tag: a..z, aa, ab, ... */
export function tagFor(index) {
  let n = index + 1;
  let s = "";
  while (n > 0) {
    n--;
    s = String.fromCharCode(97 + (n % 26)) + s;
    n = Math.floor(n / 26);
  }
  return s;
}

// --------------------------------------------------------------- tag map plan

/**
 * Plan the ordered list of tagged slots from the collection config alone
 * (no parsed data needed) so it can be previewed before running.
 * Returns: [{ tag, key, category, label }]
 */
export function buildTagMap(config) {
  const slots = [];
  let idx = 0;
  const push = (key, category, label) =>
    slots.push({ tag: tagFor(idx++), key, category, label });

  if (config.interfacesAll && config.interfacesAll.enabled) {
    const m = config.interfacesAll.mode === "ip" ? "IP only" : "full";
    push("iface:all", "Interfaces", `All interfaces (${m})`);
  } else {
    (config.interfaces || []).forEach((it, i) => {
      const mode = it.mode === "ip" ? "IP only" : "full";
      push(`iface:${i}`, "Interfaces", `${it.name} (${mode})`);
    });
  }

  const r = config.routing || {};
  if (r.defaultGateway) push("route:default", "Routing", "Default route");
  if (r.allStatic) push("route:static", "Routing", "All static routes");
  if (r.protocols) push("route:protocols", "Routing", "Routing protocols");
  if (config.vrf && config.vrf.enabled) push("vrf", "VRF", "VRFs");
  if (config.stp && config.stp.enabled) push("stp", "Spanning tree", "Spanning tree");
  if (config.dhcp && config.dhcp.enabled) push("dhcp", "DHCP", "DHCP scopes");
  if (config.snmp && config.snmp.enabled) push("snmp", "Management", "SNMP");
  if (config.tacacs && config.tacacs.enabled) push("tacacs", "Management", "TACACS+");
  if (config.logging && config.logging.enabled) push("logging", "Management", "Logging");
  if (config.ntp && config.ntp.enabled) push("ntp", "Management", "NTP");

  // Hardening is a named marker, not lettered (avoids drift).
  slots.push({ tag: "harden", key: "harden", category: "Hardening", label: "Hardening" });
  return slots;
}

// ------------------------------------------------------------- block builders

const NOT_FOUND = (what) => [`! ${what}: not found in source`];

/** Modernised default route from whatever form the source used (§12.2). */
export function defaultRouteLine(parsed) {
  if (!parsed.defaultGateway) return null;
  return `ip route 0.0.0.0 0.0.0.0 ${parsed.defaultGateway.nextHop}`;
}

function vlanUnion(vlanConfig) {
  const set = new Set();
  for (const v of vlanConfig || []) {
    for (const part of String(v.vlans).split(",")) set.add(part.trim());
  }
  return [...set].filter(Boolean).join(",");
}

/**
 * Build the spanning-tree block for a given role in the scan-wide root election.
 * role: 'root' | 'nonroot' | 'asis'. vlans: explicit vlan list (string) or null.
 */
export function buildSpanningTreeBlock(parsed, role = "asis", vlans = null) {
  const stp = parsed.spanningTree || {};
  const lines = [];
  if (stp.mode) lines.push(`spanning-tree mode ${stp.mode}`);
  if (stp.extendSystemId) lines.push("spanning-tree extend system-id");
  for (const g of stp.globalOptions || []) lines.push(g);

  const list = vlans || vlanUnion(stp.vlanConfig) || "1-4094";
  for (const v of stp.vlanConfig || []) {
    if (role !== "asis" && v.root) continue; // re-assert root role below
    lines.push(v.raw);
  }
  const mst = stp.mode === "mst";
  if (role === "root") {
    lines.push(mst ? "spanning-tree mst 0 root primary" : `spanning-tree vlan ${list} root primary`);
  } else if (role === "nonroot") {
    lines.push(
      mst ? "spanning-tree mst 0 root secondary" : `spanning-tree vlan ${list} root secondary`
    );
  }

  if (stp.mstConfig && stp.mstConfig.block) lines.push(...stp.mstConfig.block);
  return lines;
}

function buildVrfBlock(parsed) {
  const lines = [];
  for (const vrf of parsed.vrfs || []) {
    lines.push(`! ---- VRF ${vrf.name} ----`);
    lines.push(...vrf.block);
    if (vrf.interfaces.length) lines.push(`! bound interfaces: ${vrf.interfaces.join(", ")}`);
    lines.push(...vrf.routes);
  }
  return lines;
}

function buildDhcpBlock(parsed) {
  const lines = [];
  lines.push(...(parsed.excludedAddresses || []));
  for (const pool of parsed.dhcpPools || []) lines.push(...pool.block);
  for (const h of parsed.helperAddresses || [])
    lines.push(`! relay: ${h.interface} ip helper-address ${h.ip}`);
  return lines;
}

/**
 * Produce the concrete extracted lines for each planned slot.
 * opts: { stpRole, stpVlans }
 * Returns the tag map with `lines` + `found` filled in.
 */
export function buildBlocks(config, parsed, opts = {}) {
  const slots = buildTagMap(config);
  for (const slot of slots) {
    const r = fillSlot(slot, config, parsed, opts);
    slot.lines = r.lines;
    slot.found = r.found;
  }
  return slots;
}

function fillSlot(slot, config, parsed, opts) {
  if (slot.key === "iface:all") {
    const mode = (config.interfacesAll && config.interfacesAll.mode) || "full";
    const lines = [];
    let found = false;
    for (const f of parsed.interfaces || []) {
      if (mode === "ip") {
        if (!f.ipAddresses.length) continue;
        lines.push(`interface ${f.normName}`, ...f.ipAddresses.map((l) => " " + l));
      } else {
        lines.push(...f.block);
      }
      found = true;
    }
    return found ? { lines, found: true } : { lines: NOT_FOUND("interfaces"), found: false };
  }
  if (slot.key.startsWith("iface:")) {
    const i = Number(slot.key.split(":")[1]);
    const def = config.interfaces[i];
    const want = normalizeInterfaceName(def.name);
    const iface = (parsed.interfaces || []).find((f) => f.normName === want);
    if (!iface) return { lines: NOT_FOUND(`interface ${def.name}`), found: false };
    if (def.mode === "ip") {
      if (!iface.ipAddresses.length) return { lines: NOT_FOUND(`ip on ${def.name}`), found: false };
      return { lines: [`interface ${iface.normName}`, ...iface.ipAddresses.map((l) => " " + l)], found: true };
    }
    return { lines: iface.block.slice(), found: true };
  }

  switch (slot.key) {
    case "route:default": {
      const line = defaultRouteLine(parsed);
      return line ? { lines: [line], found: true } : { lines: NOT_FOUND("default route"), found: false };
    }
    case "route:static": {
      const routes = (parsed.staticRoutes || []).concat(parsed.ipv6Routes || []);
      return routes.length ? { lines: routes, found: true } : { lines: NOT_FOUND("static routes"), found: false };
    }
    case "route:protocols": {
      const lines = [];
      for (const p of parsed.protocols || []) lines.push(...p.block);
      return lines.length ? { lines, found: true } : { lines: NOT_FOUND("routing protocols"), found: false };
    }
    case "vrf": {
      const lines = buildVrfBlock(parsed);
      return lines.length ? { lines, found: true } : { lines: NOT_FOUND("VRFs"), found: false };
    }
    case "stp": {
      const stp = parsed.spanningTree || {};
      const hasStp =
        stp.mode || (stp.vlanConfig && stp.vlanConfig.length) || stp.mstConfig || (stp.raw && stp.raw.length);
      if (!hasStp) return { lines: NOT_FOUND("spanning-tree"), found: false }; // e.g. a router — never emit STP root lines
      const lines = buildSpanningTreeBlock(parsed, opts.stpRole || "asis", opts.stpVlans || null);
      return lines.length ? { lines, found: true } : { lines: NOT_FOUND("spanning-tree"), found: false };
    }
    case "dhcp": {
      const lines = buildDhcpBlock(parsed);
      return lines.length ? { lines, found: true } : { lines: NOT_FOUND("DHCP"), found: false };
    }
    case "snmp":
      return (parsed.snmp || []).length
        ? { lines: parsed.snmp, found: true }
        : { lines: NOT_FOUND("SNMP"), found: false };
    case "tacacs":
      return (parsed.tacacs || []).length
        ? { lines: parsed.tacacs, found: true }
        : { lines: NOT_FOUND("TACACS+"), found: false };
    case "logging":
      return (parsed.logging || []).length
        ? { lines: parsed.logging, found: true }
        : { lines: NOT_FOUND("logging"), found: false };
    case "ntp":
      return (parsed.ntp || []).length
        ? { lines: parsed.ntp, found: true }
        : { lines: NOT_FOUND("NTP"), found: false };
    case "harden":
      return { lines: opts.hardenLines || [], found: (opts.hardenLines || []).length > 0 };
    default:
      return { lines: [], found: false };
  }
}

// ----------------------------------------------------------------- insertion

const TAG_RE = /\{([a-z]+|harden)\}/g;

export function renderTagBased(templateText, slots) {
  const warnings = [];
  const byTag = new Map(slots.map((s) => [s.tag, s]));
  const used = new Set();
  const REMOVE = "\u0000REMOVE\u0000";

  let out = String(templateText).replace(TAG_RE, (_m, tag) => {
    const slot = byTag.get(tag);
    if (!slot) {
      warnings.push(`Marker {${tag}} has no matching collected data - line removed.`);
      return REMOVE;
    }
    used.add(tag);
    if (!slot.found) warnings.push(`Marker {${tag}} (${slot.label}): data not found in source.`);
    return (slot.lines || []).join("\n");
  });

  out = out
    .split("\n")
    .filter((l) => !l.includes(REMOVE))
    .join("\n");

  // Surface data loss: collected blocks the template never placed.
  for (const s of slots) {
    if (!used.has(s.tag) && s.found) {
      warnings.push(`Collected "${s.label}" ({${s.tag}}) has no marker in the template - its data was NOT inserted.`);
    }
  }
  return { content: out, warnings };
}

export function renderDirect(templateText, slots) {
  const warnings = [];
  const parts = [String(templateText).replace(/\s+$/, "")];
  const byCategory = new Map();
  for (const slot of slots) {
    if (slot.tag === "harden") continue; // hardening appended last under its own header
    if (!byCategory.has(slot.category)) byCategory.set(slot.category, []);
    byCategory.get(slot.category).push(slot);
  }
  for (const [category, catSlots] of byCategory) {
    parts.push("", `! ==== ${category} ====`);
    for (const slot of catSlots) {
      if (!slot.found) warnings.push(`${slot.label}: data not found in source.`);
      parts.push(...(slot.lines || []));
    }
  }
  const harden = slots.find((s) => s.tag === "harden");
  if (harden && (harden.lines || []).length) {
    parts.push("", "! ==== Hardening ====", ...harden.lines);
  }
  return { content: parts.join("\n") + "\n", warnings };
}

// ------------------------------------------------------------------- naming

export function computeOutput(parsed, naming = {}) {
  const original = parsed.hostname || "device";
  let host = original;
  if (naming.rename && naming.find) {
    if (naming.method === "suffix") {
      host = original.replace(new RegExp(escapeRegex(naming.find) + "$"), naming.replace || "");
    } else {
      host = original.split(naming.find).join(naming.replace || "");
    }
  }
  const ext = "." + String(naming.extension || "txt").replace(/^\.+/, ""); // fixed .txt by default (§12.3)
  return { original, hostname: host, filename: host + ext };
}

/**
 * Generate a secure local-admin + SSH access block from user-supplied credentials.
 * Produces SHA-256 user/enable secrets, AAA local login, optional type-6 password
 * encryption, and the SSH/VTY login commands needed to make it work. Returns [] if
 * username or password is missing.
 */
export function buildSecureAccess({ username, password, enableSecret, configKey } = {}) {
  if (!username || !password) return [];
  const lines = [
    `username ${username} privilege 15 algorithm-type sha256 secret ${password}`,
    "!",
    `enable algorithm-type sha256 secret ${enableSecret || password}`,
    "!",
    "aaa new-model",
    "aaa authentication login default local",
    "aaa authorization exec default local",
  ];
  if (configKey) {
    lines.push("!", `key config-key password-encrypt ${configKey}`, "password encryption aes");
  }
  lines.push(
    "!",
    "ip ssh version 2",
    "!",
    "line con 0",
    " login authentication default",
    "line vty 0 15",
    " transport input ssh",
    " login authentication default"
  );
  return lines;
}

/**
 * VTP version 3 block for switch templates. Mode defaults to transparent.
 * Returns [] without a domain.
 */
export function buildVtp({ domain, password, mode } = {}) {
  if (!domain) return [];
  const lines = [`vtp domain ${domain}`, "vtp version 3", `vtp mode ${mode || "transparent"}`];
  if (password) lines.push(`vtp password ${password}`);
  return lines;
}

/** Rewrite (or insert) the in-config hostname line (§12.4: default on with rename). */
export function applyHostname(content, hostname) {
  if (/^hostname\s+\S+/m.test(content)) {
    return content.replace(/^hostname\s+\S+.*$/m, `hostname ${hostname}`);
  }
  return `hostname ${hostname}\n${content}`;
}

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
