/* Verify: pair generated (or hand-edited) outputs with their source configs,
 * confirm IP addressing / VLANs / default gateway carried across, and add
 * ticked hardening fixes to an output. Pure — browser- and Node-importable.
 */

import { normalizeInterfaceName } from "./parser.js";
import { remediationLines } from "./hardening.js";
import { insertAfterDomainName } from "./template.js";

const DEFAULT_VLANS = new Set([1, 1002, 1003, 1004, 1005]); // always exist on the switch

const baseName = (name) => String(name || "").replace(/\.[^.]+$/, "").replace(/_hardened$/i, "");
const lower = (s) => String(s || "").toLowerCase();
const dirName = (path) => {
  const parts = String(path || "").split("/");
  return lower(parts.length > 1 ? parts[parts.length - 2] : "");
};

// ------------------------------------------------------------------ pairing

/**
 * Pick the source a single output belongs to. Filename first; where that is
 * ambiguous or finds nothing, the source's `hostname` decides (Crucible names
 * its outputs after the hostname, so the output's filename counts as well as
 * its own hostname line). Several sources with that hostname are narrowed by
 * matching site folder name. Returns { source, by } or null.
 */
export function pairOutput(output, sources) {
  const outBase = lower(baseName(output.name));
  const sameFile = sources.filter((s) => lower(baseName(s.name)) === outBase);
  if (sameFile.length === 1) return { source: sameFile[0], by: "filename" };

  const pool = sameFile.length > 1 ? sameFile : sources;
  const outHost = lower(output.parsed && output.parsed.hostname);
  let byHost = pool.filter((s) => {
    const h = lower(s.parsed && s.parsed.hostname);
    return h && (h === outHost || h === outBase);
  });
  if (byHost.length > 1) {
    const sameDir = byHost.filter((s) => dirName(s.path) === dirName(output.path));
    if (sameDir.length === 1) byHost = sameDir;
  }
  if (byHost.length === 1) return { source: byHost[0], by: "hostname" };

  if (sameFile.length > 1) {
    const sameDir = sameFile.filter((s) => dirName(s.path) === dirName(output.path));
    if (sameDir.length === 1) return { source: sameDir[0], by: "filename" };
  }
  return null;
}

/** Pair every output. Returns { pairs: [{ output, source|null, by|null }], unusedSources }. */
export function pairFiles(sources, outputs) {
  const used = new Set();
  const pairs = outputs.map((output) => {
    const hit = pairOutput(output, sources);
    if (hit) used.add(hit.source);
    return { output, source: hit ? hit.source : null, by: hit ? hit.by : null };
  });
  return { pairs, unusedSources: sources.filter((s) => !used.has(s)) };
}

// ------------------------------------------------------------------ compare

/** Numeric addresses on a config's interfaces: [{ key: "ip mask", iface, secondary }]. */
function addressesOf(parsed) {
  const out = [];
  for (const f of parsed.interfaces || []) {
    for (const l of f.ipAddresses || []) {
      const m = l.match(/^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(\s+secondary)?/);
      if (m) out.push({ key: `${m[1]} ${m[2]}`, iface: f.normName, secondary: !!m[3] });
    }
  }
  return out;
}

/**
 * Compare a source config with its output.
 *  ip:      every source address must appear in the output (any interface);
 *           `extra` are output-only addresses (information, not an error).
 *  remapped: interfaces that changed name — by address (certain) or by a
 *           description unique on both sides (likely).
 *  vlans:   every VLAN the source defines must be defined in the output.
 *  gateway: must point at the same next hop; `ip default-gateway` and a
 *           default route to the same address count as a match.
 */
export function compareConfigs(src, out) {
  // --- IP addressing
  const srcAddrs = addressesOf(src);
  const outAddrs = addressesOf(out);
  const outByKey = new Map();
  for (const a of outAddrs) if (!outByKey.has(a.key)) outByKey.set(a.key, a);
  const srcKeys = new Set(srcAddrs.map((a) => a.key));

  const matched = [];
  const missing = [];
  const remapped = [];
  for (const a of srcAddrs) {
    const hit = outByKey.get(a.key);
    if (!hit) {
      missing.push(a);
      continue;
    }
    matched.push(a);
    if (hit.iface !== a.iface && !remapped.some((r) => r.from === a.iface && r.to === hit.iface)) {
      remapped.push({ from: a.iface, to: hit.iface, basis: "address", detail: a.key });
    }
  }
  const extra = outAddrs.filter((a) => !srcKeys.has(a.key));

  // --- interfaces renamed without an address: unique description on both sides
  const outNames = new Set((out.interfaces || []).map((f) => f.normName));
  const srcNames = new Set((src.interfaces || []).map((f) => f.normName));
  const uniqueByDesc = (ifaces) => {
    const m = new Map();
    for (const f of ifaces || []) {
      if (!f.description) continue;
      m.set(f.description, m.has(f.description) ? null : f);
    }
    return m;
  };
  const outDesc = uniqueByDesc(out.interfaces);
  for (const [desc, f] of uniqueByDesc(src.interfaces)) {
    const o = outDesc.get(desc);
    if (!f || !o || outNames.has(f.normName) || srcNames.has(o.normName)) continue;
    if (remapped.some((r) => r.from === f.normName || r.to === o.normName)) continue;
    remapped.push({ from: f.normName, to: o.normName, basis: "description", detail: desc });
  }
  const remappedFrom = new Set(remapped.map((r) => r.from));
  const remappedTo = new Set(remapped.map((r) => r.to));
  const onlyInSource = [...srcNames].filter((n) => !outNames.has(n) && !remappedFrom.has(n));
  const onlyInOutput = [...outNames].filter((n) => !srcNames.has(n) && !remappedTo.has(n));

  // --- VLANs
  const outVlans = new Map((out.vlans || []).map((v) => [v.id, v]));
  const srcVlans = (src.vlans || []).filter((v) => !DEFAULT_VLANS.has(v.id));
  const srcVlanIds = new Set(srcVlans.map((v) => v.id));
  const vlans = {
    matched: srcVlans.filter((v) => outVlans.has(v.id)).length,
    missing: srcVlans.filter((v) => !outVlans.has(v.id)).map((v) => ({ id: v.id, name: v.name })),
    extra: (out.vlans || []).filter((v) => !srcVlanIds.has(v.id) && !DEFAULT_VLANS.has(v.id)).map((v) => ({ id: v.id, name: v.name })),
    renamed: srcVlans
      .filter((v) => outVlans.has(v.id) && v.name && outVlans.get(v.id).name && v.name !== outVlans.get(v.id).name)
      .map((v) => ({ id: v.id, from: v.name, to: outVlans.get(v.id).name })),
  };

  // --- default gateway
  const sg = src.defaultGateway;
  const og = out.defaultGateway;
  let gateway;
  if (!sg && !og) gateway = { status: "none", ok: true };
  else if (sg && !og) gateway = { status: "missing", ok: false, source: sg.nextHop };
  else if (!sg && og) gateway = { status: "added", ok: true, output: og.nextHop };
  else if (sg.nextHop === og.nextHop)
    gateway = { status: "match", ok: true, source: sg.nextHop, output: og.nextHop, converted: sg.source !== og.source };
  else gateway = { status: "mismatch", ok: false, source: sg.nextHop, output: og.nextHop };

  return {
    ip: { matched, missing, extra, ok: missing.length === 0 },
    interfaces: { remapped, onlyInSource, onlyInOutput },
    vlans: { ...vlans, ok: vlans.missing.length === 0 },
    gateway,
    ok: missing.length === 0 && vlans.missing.length === 0 && gateway.ok,
  };
}

// ---------------------------------------------------------------- hardening

/** `CVS-basement-sw.txt` → `CVS-basement-sw_hardened.txt` (extension kept). */
export function hardenedName(name) {
  const m = String(name).match(/^(.*?)(\.[^./]+)?$/);
  return `${m[1].replace(/_hardened$/i, "")}_hardened${m[2] || ""}`;
}

const isIndented = (l) => /^[ \t]/.test(l);

/**
 * Add the ticked (`apply`) hardening fixes to a config's text, keeping
 * everything else — hand edits included — as it is.
 *  - Fixes go in under a `! ==== Hardening ====` header straight after the
 *    `ip domain name` line (or at the end when there is none).
 *  - A per-interface fix is merged into that interface's existing block.
 *  - A line a fix negates (`ip http server` for `no ip http server`) or
 *    replaces (a plaintext `username … password`) is removed, since left in
 *    place further down the file it would undo the fix.
 * Returns { content, added, removed: [lines], placeholders: [tokens] }.
 */
export function applyHardening(text, findings) {
  const crlf = /\r\n/.test(String(text));
  let lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  const rem = remediationLines(findings);
  if (!rem.length) return { content: String(text), added: 0, removed: [], placeholders: [] };

  // Split the remediation into interface stanzas and everything else.
  const general = [];
  const stanzas = []; // { name, children }
  for (let i = 0; i < rem.length; i++) {
    const m = rem[i].match(/^interface\s+(\S+)/);
    if (!m) {
      general.push(rem[i]);
      continue;
    }
    const children = [];
    while (i + 1 < rem.length && isIndented(rem[i + 1])) children.push(rem[++i]);
    stanzas.push({ name: m[1], children });
  }

  // Merge interface fixes into the existing interface block where there is one.
  let added = 0;
  for (const s of stanzas) {
    const want = normalizeInterfaceName(s.name);
    const at = lines.findIndex((l) => {
      const m = l.match(/^interface\s+(\S+)/);
      return m && normalizeInterfaceName(m[1]) === want;
    });
    if (at < 0) {
      general.push(`interface ${s.name}`, ...s.children);
      continue;
    }
    let end = at;
    while (end + 1 < lines.length && isIndented(lines[end + 1]) && lines[end + 1].trim() !== "") end++;
    const have = new Set(lines.slice(at + 1, end + 1).map((l) => l.trim()));
    const fresh = s.children.filter((c) => !have.has(c.trim()));
    lines.splice(end + 1, 0, ...fresh);
    added += fresh.length;
  }

  // Lines the fixes negate or replace must not survive further down the file.
  const negated = general.filter((l) => /^no \S/.test(l)).map((l) => l.slice(3).trim());
  const resecured = general.map((l) => l.match(/^username\s+(\S+)\s.*\bsecret\b/)).filter(Boolean).map((m) => m[1]);
  const removed = [];
  lines = lines.filter((l) => {
    if (isIndented(l)) return true;
    const t = l.trim();
    const u = t.match(/^username\s+(\S+)\s.*\bpassword\b/);
    const gone = negated.some((n) => t === n || t.startsWith(n + " ")) || (u && resecured.includes(u[1]));
    if (gone) removed.push(t);
    return !gone;
  });

  // Don't ask for a second RSA key when the file already generates one.
  const hasRsa = lines.some((l) => /^crypto key generate rsa\b/.test(l));
  const block = general.filter((l) => !(hasRsa && /^crypto key generate rsa\b/.test(l)));
  // Drop a comment/separator left with nothing under it.
  const tidy = block.filter((l, i) => !(l === "!" && (i === 0 || i === block.length - 1 || block[i - 1] === "!")));

  let content = lines.join("\n");
  if (tidy.length) {
    content = insertAfterDomainName(content, ["!", "! ==== Hardening ====", ...tidy]).content;
    added += tidy.filter((l) => !/^!/.test(l)).length;
  }
  const placeholders = [...new Set((content.match(/<[A-Z][A-Z-]*>/g) || []))];
  return { content: crlf ? content.replace(/\n/g, "\r\n") : content, added, removed, placeholders };
}
