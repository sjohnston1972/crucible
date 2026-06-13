import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../public/lib/parser.js";
import {
  tagFor,
  buildTagMap,
  buildBlocks,
  defaultRouteLine,
  buildSpanningTreeBlock,
  renderTagBased,
  renderDirect,
  computeOutput,
  applyHostname,
  buildSecureAccess,
} from "../public/lib/template.js";

const CFG = {
  interfaces: [
    { name: "Gi1/0/1", mode: "full" },
    { name: "Vlan10", mode: "ip" },
  ],
  routing: { defaultGateway: true, allStatic: true, protocols: true },
  vrf: { enabled: true },
  stp: { enabled: true },
  dhcp: { enabled: true },
};

const SRC = parse(`hostname Lab1
interface GigabitEthernet1/0/1
 description Uplink
 switchport mode trunk
!
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
!
ip default-gateway 192.168.1.1
ip route 10.0.0.0 255.0.0.0 10.1.1.1
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
!
vrf definition RED
 rd 1:1
!
spanning-tree mode rapid-pvst
spanning-tree vlan 10 priority 8192
ip dhcp excluded-address 10.1.10.1 10.1.10.9
ip dhcp pool DATA
 network 10.1.10.0 255.255.255.0
!
`);

test("tagFor sequences a..z then aa", () => {
  assert.equal(tagFor(0), "a");
  assert.equal(tagFor(25), "z");
  assert.equal(tagFor(26), "aa");
  assert.equal(tagFor(27), "ab");
});

test("buildTagMap is stable: interfaces lettered, categories single, harden named", () => {
  const map = buildTagMap(CFG);
  assert.deepEqual(
    map.map((s) => `${s.tag}:${s.key}`),
    [
      "a:iface:0",
      "b:iface:1",
      "c:route:default",
      "d:route:static",
      "e:route:protocols",
      "f:vrf",
      "g:stp",
      "h:dhcp",
      "harden:harden",
    ]
  );
});

test("all-interfaces mode: one slot emits every interface block", () => {
  const cfg = { interfacesAll: { enabled: true, mode: "full" }, routing: {}, vrf: {}, stp: {}, dhcp: {} };
  const map = buildTagMap(cfg);
  assert.equal(map[0].tag, "a");
  assert.equal(map[0].key, "iface:all");
  assert.match(map[0].label, /All interfaces \(full\)/);

  const slots = buildBlocks(cfg, SRC, {});
  const all = slots.find((s) => s.key === "iface:all");
  const text = all.lines.join("\n");
  assert.match(text, /interface GigabitEthernet1\/0\/1/);
  assert.match(text, /interface Vlan10/);
  assert.match(text, /switchport mode trunk/); // full block, not ip-only
});

test("all-interfaces IP-only mode emits only addressed interfaces", () => {
  const cfg = { interfacesAll: { enabled: true, mode: "ip" }, routing: {}, vrf: {}, stp: {}, dhcp: {} };
  const slots = buildBlocks(cfg, SRC, {});
  const text = slots.find((s) => s.key === "iface:all").lines.join("\n");
  assert.match(text, /interface Vlan10/);
  assert.match(text, /ip address 10\.1\.10\.1/);
  assert.doesNotMatch(text, /switchport mode trunk/); // Gi1/0/1 has no IP → only its header would appear; trunk line excluded
});

test("default route modernised from ip default-gateway", () => {
  assert.equal(defaultRouteLine(SRC), "ip route 0.0.0.0 0.0.0.0 192.168.1.1");
});

test("buildBlocks: full interface vs ip-only", () => {
  const slots = buildBlocks(CFG, SRC, { hardenLines: ["no ip http server"] });
  const giSlot = slots.find((s) => s.key === "iface:0");
  assert.ok(giSlot.found);
  assert.ok(giSlot.lines.join("\n").includes("switchport mode trunk"));

  const vlanSlot = slots.find((s) => s.key === "iface:1");
  assert.deepEqual(vlanSlot.lines, ["interface Vlan10", " ip address 10.1.10.1 255.255.255.0"]);

  const defSlot = slots.find((s) => s.key === "route:default");
  assert.deepEqual(defSlot.lines, ["ip route 0.0.0.0 0.0.0.0 192.168.1.1"]);
});

test("missing interface yields not-found block, not a throw", () => {
  const cfg = { interfaces: [{ name: "Gi9/9/9", mode: "full" }], routing: {}, vrf: {}, stp: {}, dhcp: {} };
  const slots = buildBlocks(cfg, SRC, {});
  const s = slots.find((x) => x.key === "iface:0");
  assert.equal(s.found, false);
  assert.ok(s.lines[0].includes("not found"));
});

test("STP root election: elected root gets root primary, non-root secondary", () => {
  const rootLines = buildSpanningTreeBlock(SRC, "root", "10");
  assert.ok(rootLines.includes("spanning-tree vlan 10 root primary"));
  const nonRoot = buildSpanningTreeBlock(SRC, "nonroot", "10");
  assert.ok(nonRoot.includes("spanning-tree vlan 10 root secondary"));
});

test("STP slot is not emitted for a device with no spanning-tree (router)", () => {
  const cfg = { interfacesAll: { enabled: false }, interfaces: [], routing: {}, vrf: {}, stp: { enabled: true }, dhcp: {} };
  const router = parse("hostname RTR\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n!\n");
  const slots = buildBlocks(cfg, router, { stpRole: "nonroot", stpVlans: "1-10" });
  const stpSlot = slots.find((s) => s.key === "stp");
  assert.equal(stpSlot.found, false);
  assert.doesNotMatch(stpSlot.lines.join("\n"), /root secondary/); // router must not get STP root lines
});

test("renderTagBased replaces markers and removes unmatched lines", () => {
  const slots = buildBlocks(CFG, SRC, { hardenLines: ["no ip http server"] });
  const template = [
    "hostname TARGET",
    "{a}",
    "!",
    "{c}",
    "{harden}",
    "{zz}", // no matching data -> removed + warn
    "end",
  ].join("\n");
  const { content, warnings } = renderTagBased(template, slots);
  assert.ok(content.includes("switchport mode trunk"));
  assert.ok(content.includes("ip route 0.0.0.0 0.0.0.0 192.168.1.1"));
  assert.ok(content.includes("no ip http server"));
  assert.ok(!content.includes("{zz}"));
  assert.ok(warnings.some((w) => w.includes("{zz}")));
});

test("renderTagBased warns when a collected block has no marker (data loss)", () => {
  const slots = buildBlocks(CFG, SRC, { hardenLines: [] });
  // template only places {a}; {b} (Vlan10 ip) and others have data but no marker
  const { warnings } = renderTagBased("hostname X\n{a}\nend", slots);
  assert.ok(warnings.some((w) => /\{b\}/.test(w) && /NOT inserted/.test(w)));
});

test("renderDirect appends section headers in order", () => {
  const slots = buildBlocks(CFG, SRC, { hardenLines: ["no ip http server"] });
  const { content } = renderDirect("hostname TARGET\n!", slots);
  assert.ok(content.includes("! ==== Interfaces ===="));
  assert.ok(content.includes("! ==== Routing ===="));
  assert.ok(content.includes("! ==== Spanning tree ===="));
  assert.ok(content.includes("! ==== Hardening ===="));
  assert.ok(content.indexOf("! ==== Interfaces ====") < content.indexOf("! ==== Hardening ===="));
});

test("management slots carry SNMP/TACACS/logging/NTP", () => {
  const cfg = {
    interfacesAll: { enabled: false },
    interfaces: [],
    routing: {},
    vrf: {},
    stp: {},
    dhcp: {},
    snmp: { enabled: true },
    ntp: { enabled: true },
  };
  const src = parse("snmp-server community x RO\nntp server 1.1.1.1\n");
  const map = buildTagMap(cfg);
  assert.ok(map.some((s) => s.key === "snmp" && s.label === "SNMP"));
  assert.ok(map.some((s) => s.key === "ntp"));
  const slots = buildBlocks(cfg, src, {});
  assert.match(slots.find((s) => s.key === "snmp").lines.join("\n"), /snmp-server community x RO/);
  assert.match(slots.find((s) => s.key === "ntp").lines.join("\n"), /ntp server 1\.1\.1\.1/);
});

test("buildSecureAccess: SHA-256 secrets, AAA local, type-6, SSH/VTY", () => {
  const lines = buildSecureAccess({ username: "netadmin", password: "Sec!", configKey: "Key1" }).join("\n");
  assert.match(lines, /^username netadmin privilege 15 algorithm-type sha256 secret Sec!/m);
  assert.match(lines, /^enable algorithm-type sha256 secret Sec!/m);
  assert.match(lines, /^aaa authentication login default local/m);
  assert.match(lines, /^key config-key password-encrypt Key1/m);
  assert.match(lines, /^password encryption aes/m);
  assert.match(lines, /^ip ssh version 2/m);
  assert.match(lines, / transport input ssh/);
  assert.match(lines, / login authentication default/);
});

test("buildSecureAccess: enable secret defaults to password; empty without creds", () => {
  assert.match(buildSecureAccess({ username: "u", password: "p" }).join("\n"), /enable algorithm-type sha256 secret p/);
  assert.deepEqual(buildSecureAccess({ username: "u" }), []);
  assert.deepEqual(buildSecureAccess({}), []);
});

test("computeOutput: rename find/replace + fixed .txt extension", () => {
  const out = computeOutput(parse("hostname abccorp_RT1\n"), {
    rename: true,
    method: "find",
    find: "RT",
    replace: "SW",
  });
  assert.equal(out.original, "abccorp_RT1");
  assert.equal(out.hostname, "abccorp_SW1");
  assert.equal(out.filename, "abccorp_SW1.txt");
});

test("computeOutput: no rename → hostname.txt", () => {
  const out = computeOutput(parse("hostname Core9\n"), {});
  assert.equal(out.filename, "Core9.txt");
});

test("applyHostname rewrites the hostname line", () => {
  const c = applyHostname("hostname OLD\ninterface Vlan1\n", "NEW");
  assert.ok(c.startsWith("hostname NEW"));
});
