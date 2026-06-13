/* Redaction + structural digest for the AI hardening endpoint.
 *
 * Hard rule: secrets never leave the browser. We send the Worker a structural
 * digest (counts, names, derived service flags) — never password hashes, SNMP
 * community strings, keys/PSKs, or certificate material.
 */

const SECRET_PATTERNS = [
  /(\bsecret\s+\d+\s+)\S+/gi, // enable/username secret 5 <hash>
  /(\bpassword\s+\d+\s+)\S+/gi, // password 7 <hash>
  /(\bsnmp-server community\s+)\S+/gi, // community strings
  /(\bkey\s+\d+\s+)\S+/gi, // tacacs/ntp key 7 <hash>
  /(\bpre-shared-key\b.*?\s)\S+$/gim,
  /(\bmd5\s+)\S+/gi,
];

/** Mask secrets in raw config text (defence-in-depth if raw text is ever sent). */
export function maskSecrets(text) {
  let out = String(text == null ? "" : text);
  for (const re of SECRET_PATTERNS) out = out.replace(re, "$1<redacted>");
  // certificate / key hex blocks (lines of grouped hex)
  out = out.replace(/^(\s*)([0-9A-F]{8}\s+){2,}[0-9A-F ]*$/gim, "$1<redacted-cert-data>");
  return out;
}

/** Build a secrets-free structural digest of a parsed config. */
export function buildSummary(parsed) {
  const interfaces = parsed.interfaces || [];
  const byKind = {};
  let trunks = 0;
  let access = 0;
  const svis = [];
  for (const f of interfaces) {
    const kind = (f.normName.match(/^[A-Za-z-]+/) || ["?"])[0];
    byKind[kind] = (byKind[kind] || 0) + 1;
    if (f.switchportLines.some((l) => /mode trunk/.test(l))) trunks++;
    if (f.switchportLines.some((l) => /mode access/.test(l))) access++;
    if (f.hasIp) svis.push({ name: f.normName, addresses: f.ipAddresses.length });
  }

  const hasL2 =
    trunks > 0 ||
    access > 0 ||
    !!parsed.spanningTree.mode ||
    interfaces.some((f) => f.switchportLines.length);
  const role = hasL2 ? (parsed.isL3 ? "l3-switch" : "l2-switch") : "router";

  return {
    hostname: parsed.hostname,
    role, // 'router' | 'l2-switch' | 'l3-switch' — drives role-appropriate AI suggestions
    layer3: !!parsed.isL3,
    interfaceCount: interfaces.length,
    interfacesByKind: byKind,
    trunkPorts: trunks,
    accessPorts: access,
    routedInterfaces: svis,
    defaultGateway: parsed.defaultGateway
      ? { present: true, via: parsed.defaultGateway.source }
      : { present: false },
    staticRouteCount: (parsed.staticRoutes || []).length,
    routingProtocols: (parsed.protocols || []).map((p) => `${p.type} ${p.id}`.trim()),
    vrfs: (parsed.vrfs || []).map((v) => v.name),
    spanningTree: {
      mode: parsed.spanningTree.mode,
      perVlanEntries: parsed.spanningTree.vlanConfig.length,
      mst: !!parsed.spanningTree.mstConfig,
    },
    dhcpPools: (parsed.dhcpPools || []).map((p) => p.name),
    dhcpRelays: (parsed.helperAddresses || []).length,
  };
}

/** Payload for POST /api/harden: { hostname, summary }. Contains no secrets. */
export function redactForAI(parsed) {
  return { hostname: parsed.hostname, summary: buildSummary(parsed) };
}
