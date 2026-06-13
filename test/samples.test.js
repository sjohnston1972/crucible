import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { parse } from "../public/lib/parser.js";
import { audit } from "../public/lib/hardening.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(join(__dirname, "..", "samples", p), "utf8");
const find = (fs, id) => fs.find((f) => f.id === id);

test("sample RT1: router with VRF, OSPF, DHCP, default route", () => {
  const p = parse(read("SiteA/RT1.txt"));
  assert.equal(p.hostname, "RT1");
  assert.equal(p.isL3, true);
  assert.equal(p.vrfs[0].name, "CUSTOMER_A");
  assert.equal(p.vrfs[0].rd, "65001:10");
  assert.ok(p.vrfs[0].interfaces.includes("GigabitEthernet0/1"));
  assert.equal(p.protocols[0].type, "ospf");
  assert.equal(p.dhcpPools[0].name, "DATA_VLAN30");
  assert.equal(p.defaultGateway.source, "default-route");
  assert.equal(p.defaultGateway.nextHop, "10.10.0.1");
});

test("router RT1: switch-only hardening checks are N/A, not suggested", () => {
  const f = audit(parse(read("SiteA/RT1.txt")));
  assert.equal(find(f, "bpduguard-default").status, "na");
  assert.equal(find(f, "portfast-without-bpduguard").status, "na");
  assert.equal(find(f, "udld-aggressive").status, "na"); // UDLD is a switch concern
  // router-relevant baseline still applies
  assert.equal(find(f, "ssh-v2").status, "pass");
  assert.equal(find(f, "ip-http-server").status, "missing"); // RT1 has 'ip http server'
});

test("switch SW1: switch-only checks still apply", () => {
  const f = audit(parse(read("SiteA/SW1.txt")));
  assert.equal(find(f, "bpduguard-default").status, "pass"); // SW1 sets the default
  assert.notEqual(find(f, "portfast-without-bpduguard").status, "na");
  assert.equal(find(f, "udld-aggressive").status, "missing"); // SW1 has no udld aggressive
});

test("sample SW1: MST config, per-vlan, known findings", () => {
  const p = parse(read("SiteA/SW1.txt"));
  assert.equal(p.spanningTree.mode, "mst");
  assert.equal(p.spanningTree.mstConfig.name, "REGION1");
  assert.equal(p.spanningTree.mstConfig.instances.length, 2);
  assert.equal(p.defaultGateway.source, "default-gateway"); // L2-style, will modernise

  const f = audit(p);
  assert.equal(find(f, "snmp-default-community").status, "missing"); // community public
  assert.equal(find(f, "vty-telnet").status, "missing"); // transport input ssh telnet
  assert.equal(find(f, "ip-http-server").status, "pass"); // no ip http server
  assert.equal(find(f, "bpduguard-default").status, "pass"); // portfast bpduguard default set
  // Gi1/0/2 has portfast but no per-port bpduguard
  const pf = find(f, "portfast-without-bpduguard");
  assert.equal(pf.status, "missing");
  assert.ok(pf.detail.includes("GigabitEthernet1/0/2"));
});
