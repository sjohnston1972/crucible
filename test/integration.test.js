import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { parse } from "../public/lib/parser.js";
import { audit, remediationLines } from "../public/lib/hardening.js";
import { buildBlocks, renderTagBased, renderDirect, computeOutput, applyHostname } from "../public/lib/template.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const bourdon = readFileSync(join(__dirname, "..", "BourdonSW1.txt"), "utf8");

// Mirrors the app's onSave() pipeline for a single device unit.
const CONFIG = {
  interfaces: [{ name: "Vlan1", mode: "ip" }],
  routing: { defaultGateway: true, allStatic: false, protocols: false },
  vrf: { enabled: false },
  stp: { enabled: true },
  dhcp: { enabled: true },
  insertion: "tag",
  naming: { rename: true, method: "find", find: "SW", replace: "L3SW" },
};

const TEMPLATE = ["hostname PLACEHOLDER", "!", "{a}", "!", "{b}", "!", "{c}", "!", "{d}", "!", "{harden}", "end"].join("\n");

test("end-to-end: Bourdon L2 → L3 template (tag-based, root election, rename, hardening)", () => {
  const parsed = parse(bourdon);
  const findings = audit(parsed);

  // user ticks the http-server hardening item
  findings.find((f) => f.id === "ip-http-server").apply = true;
  const hardenLines = remediationLines(findings);

  const slots = buildBlocks(CONFIG, parsed, {
    stpRole: "root", // this device elected as the scan's STP root
    stpVlans: null,
    hardenLines,
  });

  const { content, warnings } = renderTagBased(TEMPLATE, slots);

  // interface IP-only block
  assert.match(content, /interface Vlan1/);
  assert.match(content, /192\.168\.1\.70/);

  // default-gateway modernised to a default route (§12.2)
  assert.match(content, /ip route 0\.0\.0\.0 0\.0\.0\.0 192\.168\.1\.1/);

  // spanning-tree present + elected root
  assert.match(content, /spanning-tree mode pvst/);
  assert.match(content, /root primary/);

  // DHCP not present in Bourdon → not-found marker, not a crash
  assert.match(content, /DHCP: not found/);

  // hardening injected
  assert.match(content, /no ip http server/);

  // rename rewrites both filename and in-config hostname (§12.4)
  const naming = computeOutput(parsed, CONFIG.naming);
  assert.equal(naming.filename, "BourdonL3SW1.txt");
  const finalContent = applyHostname(content, naming.hostname);
  assert.match(finalContent, /^hostname BourdonL3SW1/m);
  assert.doesNotMatch(finalContent, /hostname PLACEHOLDER/);

  // DHCP-not-found should have produced a warning
  assert.ok(warnings.some((w) => /DHCP/.test(w)));
});

test("end-to-end: direct insertion produces section headers", () => {
  const parsed = parse(bourdon);
  const slots = buildBlocks(CONFIG, parsed, { stpRole: "asis", hardenLines: ["no ip http server"] });
  const { content } = renderDirect("hostname TARGET\n!", slots);
  assert.match(content, /! ==== Interfaces ====/);
  assert.match(content, /! ==== Routing ====/);
  assert.match(content, /! ==== Spanning tree ====/);
  assert.match(content, /! ==== Hardening ====/);
});
