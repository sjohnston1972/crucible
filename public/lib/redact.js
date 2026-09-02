/* Redaction + structural digest for the AI hardening endpoint.
 *
 * Hard rule: secrets never leave the browser. We send the Worker a structural
 * digest (counts, names, derived service flags) — never password hashes, SNMP
 * community strings, keys/PSKs, or certificate material.
 */

// NOTE: all "whitespace between keyword and value" gaps below use [ \t]+ (not
// \s+) deliberately. \s matches newlines too, and a greedy \s+ can jump past
// end-of-line and swallow the *next* line's first token as if it were the
// secret value (this bit us with the "key chain" / "key-string 7 <hash>"
// block, where a bare "key 1" sub-line let \s+ walk onto "key-string" on the
// following line). Keeping the gap horizontal-only confines every match to
// a single line.
export const SECRET_PATTERNS = [
  /(\bsecret[ \t]+\d+[ \t]+)\S+/gi, // enable/username secret 5 <hash>
  /(\bpassword[ \t]+\d+[ \t]+)\S+/gi, // password 7 <hash> (incl. type-0 plaintext)
  /(\bsnmp-server community[ \t]+)\S+/gi, // community strings
  /(\bsnmp-server host[ \t]+\S+[ \t]+(?:version[ \t]+\S+[ \t]+)?)\S+/gi, // community on "snmp-server host <ip> [version N] <community>"
  /(\bkey-string[ \t]+\d+[ \t]+)\S+/gi, // key chain key-string 7 <hash>
  /(\b(?:tacacs-server|radius-server)[ \t]+key[ \t]+\d+[ \t]+)\S+/gi, // old single-line "tacacs-server key 7 <hash>"
  /(\b(?:tacacs-server|radius-server)[ \t]+key[ \t]+)(?!\d+[ \t])\S+/gi, // old single-line bare "tacacs-server key <secret>"
  // Generic "key <digit> <value>" is intentionally anchored to a WHOLE line
  // (not "\bkey ..." anywhere in a line): tacacs/radius sub-lines and
  // key-chain entries always put "key <id> <secret>" on their own line, but
  // *unrelated* commands can legitimately end in "key <id> <keyword>" — e.g.
  // "ntp server 1.2.3.4 key 0 prefer", where "prefer" is a flag, not a
  // secret. A non-anchored match would misfire on those.
  /(^[ \t]*key[ \t]+\d+[ \t]+)\S+[ \t]*$/gim, // standalone tacacs/ntp "key 7 <hash>" line
  /(^[ \t]*key[ \t]+)(?!chain\b)(?!\d+[ \t]*$)\S+[ \t]*$/gim, // bare tacacs/radius "key <secret>" sub-line (no type digit, whole line is just "key <value>")
  /(\bpre-shared-key\b.*?[ \t])\S+$/gim,
  /(\bmd5[ \t]+)\S+/gi,
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
