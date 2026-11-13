import { test } from "node:test";
import { readFileSync } from "node:fs";
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
  buildDirectSections,
  insertAfterDomainName,
  computeOutput,
  applyHostname,
  buildSecureAccess,
  buildVtp,
  buildClock,
  buildStpHardening,
  buildErrdisable,
  buildBanner,
  applyInterfaceMap,
  detectInterfaceMapConflicts,
  stampHostname,
  convertLegacyQos,
  buildRsaKey,
} from "../public/lib/template.js";
import { audit, remediationLines } from "../public/lib/hardening.js";

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

test("generated config goes straight after the template's ip domain name line, RSA key first", () => {
  const tpl = "hostname T\n!\nip domain name corp.local\n!\ninterface Vlan1\n no ip address\n!\nline vty 0 4\n transport input ssh\n!\nend";
  const gen = [...buildRsaKey(), ...buildDirectSections(buildBlocks(CFG, SRC, {})).lines];
  const { content, placed } = insertAfterDomainName(tpl, gen);
  assert.equal(placed, true);
  const lines = content.split("\n");
  const at = lines.indexOf("ip domain name corp.local");
  assert.equal(lines[at + 1], "crypto key generate rsa modulus 2048");
  assert.equal(lines[at + 2], "!");
  assert.equal(lines[at + 3], "! ==== Interfaces ====");
  // the rest of the template still follows the generated run, intact
  assert.ok(content.indexOf("! ==== Interfaces ====") < content.indexOf("interface Vlan1\n no ip address"));
  assert.ok(content.endsWith("line vty 0 4\n transport input ssh\n!\nend"));
  assert.doesNotMatch(content, /!\n!\ninterface Vlan1\n no ip address/); // no doubled separator
});

test("insertAfterDomainName: hyphenated form matches, DHCP pool domain-name does not", () => {
  const tpl = "ip dhcp pool A\n domain-name pool.local\n!\nip domain-name corp.local\nend";
  const { content } = insertAfterDomainName(tpl, ["crypto key generate rsa modulus 2048"]);
  assert.equal(content, "ip dhcp pool A\n domain-name pool.local\n!\nip domain-name corp.local\ncrypto key generate rsa modulus 2048\n!\nend");
});

test("insertAfterDomainName: no domain name line falls back to the end; nothing to insert is a no-op", () => {
  const r = insertAfterDomainName("hostname T\n!\n", ["crypto key generate rsa modulus 2048"]);
  assert.equal(r.placed, false);
  assert.equal(r.content, "hostname T\n!\n!\ncrypto key generate rsa modulus 2048\n");
  assert.equal(insertAfterDomainName("hostname T\n", []).content, "hostname T\n");
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
  assert.match(lines, /^line con 0\n login authentication default/m);
});

test("global generators: clock, STP hardening, errdisable, banner", () => {
  assert.deepEqual(buildClock({ timezone: "GMT", offset: 0 }), ["clock timezone GMT 0"]);
  assert.ok(buildClock({ timezone: "GMT", offset: 0, summerTime: "BST recurring" }).includes("clock summer-time BST recurring"));
  assert.deepEqual(buildClock({}), []);

  assert.ok(buildStpHardening().includes("spanning-tree portfast bpduguard default"));
  assert.ok(buildStpHardening().includes("spanning-tree loopguard default"));

  const errd = buildErrdisable({ interval: 120 });
  assert.ok(errd.includes("errdisable recovery cause bpduguard"));
  assert.ok(errd.includes("errdisable recovery interval 120"));
  assert.ok(buildErrdisable({}).includes("errdisable recovery interval 300"));

  const ban = buildBanner({ text: "Authorised only" });
  assert.ok(ban.some((l) => /^banner login \^C Authorised only \^C/.test(l)));
  assert.ok(ban.some((l) => /^banner motd/.test(l)));
  assert.deepEqual(buildBanner({ text: "   " }), []);
});

test("buildVtp: version 3, transparent default, optional password; empty without domain", () => {
  assert.deepEqual(buildVtp({ domain: "CORP" }), [
    "vtp domain CORP",
    "vtp version 3",
    "vtp mode transparent",
  ]);
  const withPw = buildVtp({ domain: "CORP", password: "s3cret", mode: "server" });
  assert.ok(withPw.includes("vtp mode server"));
  assert.ok(withPw.includes("vtp password s3cret"));
  assert.deepEqual(buildVtp({}), []);
  assert.deepEqual(buildVtp({ password: "x" }), []);
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

// ----------------------------------------------------------- interface remap

const TWO_IFACES = parse(`hostname X
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet1/0/24
 description LAN
 switchport mode trunk`);

test("applyInterfaceMap renames a routed interface verbatim", () => {
  const map = new Map([["GigabitEthernet0/0/1", { target: "Gi1/0/24", transform: "routed", vlan: null }]]);
  const out = applyInterfaceMap(TWO_IFACES, map);
  const names = out.interfaces.map((f) => f.normName);
  assert.deepEqual(names, ["GigabitEthernet1/0/24"]);
  const renamed = out.interfaces.find((f) => f.normName === "GigabitEthernet1/0/24");
  assert.equal(renamed.block[0], "interface GigabitEthernet1/0/24");
  assert.ok(renamed.ipAddresses.some((l) => l.includes("10.0.0.1")));
});

test("applyInterfaceMap is a no-op for empty/self/blank maps and never mutates input", () => {
  const before = TWO_IFACES.interfaces.length;
  assert.equal(applyInterfaceMap(TWO_IFACES, new Map()), TWO_IFACES);
  const selfMap = new Map([["GigabitEthernet0/0/1", { target: "Gi0/0/1", transform: "routed", vlan: null }]]);
  assert.equal(applyInterfaceMap(TWO_IFACES, selfMap), TWO_IFACES);
  assert.equal(TWO_IFACES.interfaces.length, before);
});

test("applyInterfaceMap SVI moves L3 onto a synthesized Vlan SVI and switchports the port", () => {
  const map = new Map([["GigabitEthernet0/0/1", { target: "Gi1/0/24", transform: "svi", vlan: "60" }]]);
  const out = applyInterfaceMap(TWO_IFACES, map);
  const svi = out.interfaces.find((f) => f.normName === "Vlan60");
  assert.ok(svi, "SVI created");
  assert.ok(svi.ipAddresses.some((l) => l.includes("10.0.0.1")));
  const port = out.interfaces.find((f) => f.normName === "GigabitEthernet1/0/24");
  assert.ok(port.block.some((l) => l.includes("switchport access vlan 60")));
});

test("applyInterfaceMap SVI merges into an existing Vlan interface", () => {
  const src = parse(`hostname X
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
!
interface Vlan60
 ip address 10.0.60.1 255.255.255.0`);
  const map = new Map([["GigabitEthernet0/0/1", { target: "Gi1/0/24", transform: "svi", vlan: "60" }]]);
  const out = applyInterfaceMap(src, map);
  const svis = out.interfaces.filter((f) => f.normName === "Vlan60");
  assert.equal(svis.length, 1, "merged, not duplicated");
  assert.ok(svis[0].ipAddresses.some((l) => l.includes("10.0.0.1")));
  assert.ok(svis[0].ipAddresses.some((l) => l.includes("10.0.60.1")));
});

test("detectInterfaceMapConflicts flags duplicate targets and missing SVI vlan", () => {
  const parsed = parse("hostname X");
  const map = new Map([
    ["GigabitEthernet0/0/1", { target: "Gi1/0/24", transform: "routed", vlan: null }],
    ["GigabitEthernet0/0/2", { target: "Gi1/0/24", transform: "routed", vlan: null }],
    ["GigabitEthernet0/0/3", { target: "Gi1/0/48", transform: "svi", vlan: "" }],
  ]);
  const w = detectInterfaceMapConflicts(parsed, map, { label: "R1" });
  assert.ok(w.some((x) => x.hard && /both map to GigabitEthernet1\/0\/24/.test(x.message)));
  assert.ok(w.some((x) => x.hard && /SVI but no VLAN/.test(x.message)));
});

test("detectInterfaceMapConflicts soft-warns when a mapped target overwrites a selected sibling", () => {
  const parsed = parse(`hostname X
interface GigabitEthernet1/0/24
 switchport mode trunk`);
  const map = new Map([["GigabitEthernet0/0/1", { target: "Gi1/0/24", transform: "routed", vlan: null }]]);
  const sel = new Set(["GigabitEthernet1/0/24"]);
  const w = detectInterfaceMapConflicts(parsed, map, { label: "R1", selectedTargets: sel });
  assert.ok(w.some((x) => !x.hard && /replaced by mapped GigabitEthernet0\/0\/1/.test(x.message)));
});

test("buildBlocks emits the renamed interface from a transformed parsed", () => {
  const src = parse(`hostname X
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0`);
  const map = new Map([["GigabitEthernet0/0/1", { target: "Gi1/0/24", transform: "routed", vlan: null }]]);
  const tp = applyInterfaceMap(src, map);
  const cfg = { interfacesAll: { enabled: true, mode: "full" } };
  const slots = buildBlocks(cfg, tp);
  const all = slots.flatMap((s) => s.lines).join("\n");
  assert.ok(all.includes("interface GigabitEthernet1/0/24"));
  assert.ok(!all.includes("interface GigabitEthernet0/0/1"));
});

// ------------------------------------------------- hostname stamping (no rename)

test("stampHostname inserts the source hostname into a user template without rename", () => {
  const parsed = parse("hostname Paisley-48G-SW2\n");
  const out = stampHostname("!\nhostname TEMPLATE-NAME\n!\nend\n", parsed, { rename: false });
  assert.match(out, /^hostname Paisley-48G-SW2$/m);
  assert.doesNotMatch(out, /TEMPLATE-NAME/);
});

test("stampHostname applies the rename transform when ticked", () => {
  const parsed = parse("hostname abccorp_RT1\n");
  const out = stampHostname("hostname X\n", parsed, { rename: true, method: "suffix", find: "RT1", replace: "SW1" });
  assert.match(out, /^hostname abccorp_SW1$/m);
});

test("stampHostname leaves the template alone when the source has no hostname", () => {
  const out = stampHostname("hostname KEEP\n", parse("interface Vlan1\n"), {});
  assert.equal(out, "hostname KEEP\n");
});

// ------------------------------------------------- legacy mls qos → IOS-XE

const ifaceBlock = (p, name) => p.interfaces.find((f) => f.normName === name).block;

test("convertLegacyQos: mls qos trust cos → auto qos trust cos, legacy queueing removed", () => {
  const src = parse(`hostname X
interface GigabitEthernet0/11
 switchport access vlan 4
 srr-queue bandwidth share 10 10 60 20
 srr-queue bandwidth shape  10  0  0  0
 queue-set 2
 mls qos trust cos
 auto qos voip trust
 spanning-tree portfast`);
  const out = convertLegacyQos(src);
  assert.deepEqual(ifaceBlock(out, "GigabitEthernet0/11"), [
    "interface GigabitEthernet0/11",
    " switchport access vlan 4",
    " auto qos trust cos",
    " spanning-tree portfast",
  ]);
  // input not mutated
  assert.ok(ifaceBlock(src, "GigabitEthernet0/11").includes(" mls qos trust cos"));
});

test("convertLegacyQos: mls qos trust dscp → auto qos trust dscp", () => {
  const out = convertLegacyQos(parse("interface Gi0/1\n mls qos trust dscp\n"));
  assert.deepEqual(ifaceBlock(out, "GigabitEthernet0/1"), ["interface Gi0/1", " auto qos trust dscp"]);
});

test("convertLegacyQos: cisco-phone conditional trust → auto qos voip cisco-phone, legacy policer dropped", () => {
  const out = convertLegacyQos(parse(`interface Gi1/0/1
 switchport voice vlan 91
 srr-queue bandwidth share 10 10 60 20
 queue-set 2
 priority-queue out
 mls qos trust device cisco-phone
 mls qos trust cos
 auto qos voip cisco-phone
 service-policy input AutoQoS-Police-CiscoPhone
 spanning-tree portfast`));
  assert.deepEqual(ifaceBlock(out, "GigabitEthernet1/0/1"), [
    "interface Gi1/0/1",
    " switchport voice vlan 91",
    " auto qos voip cisco-phone",
    " spanning-tree portfast",
  ]);
});

test("convertLegacyQos: IOS-XE style interfaces are left untouched", () => {
  const src = parse(`interface Te1/1/2
 switchport mode trunk
 auto qos trust
 service-policy input AutoQos-4.0-Trust-Cos-Input-Policy
 service-policy output AutoQos-4.0-Output-Policy
!
interface Gi1/0/2
 switchport mode access`);
  assert.equal(convertLegacyQos(src), src);
});

test("convertLegacyQos: no mls qos line survives on the real legacy samples", () => {
  for (const f of ["paisley/Paisley L3 Switch.txt", "cmb/CMB-TUK-SWT02_sh run.txt"]) {
    const src = parse(readFileSync(new URL("../public/sample-data/" + f, import.meta.url), "utf8"));
    const out = convertLegacyQos(src);
    const text = out.interfaces.map((i) => i.block.join("\n")).join("\n");
    assert.doesNotMatch(text, /^\s*(mls qos|srr-queue|queue-set|priority-queue)\b/m, f);
    const legacyCount = src.interfaces.filter((i) => i.block.some((l) => /^\s*mls qos\b/.test(l))).length;
    const xeCount = out.interfaces.filter((i) => i.block.some((l) => /^ auto qos (trust (cos|dscp)|voip cisco-phone)$/.test(l))).length;
    assert.ok(legacyCount > 0 && xeCount >= legacyCount, f);
  }
});

test("convertLegacyQos survives an interface remap (Gi0/11 → Te1/1/3)", () => {
  const src = parse("interface GigabitEthernet0/11\n switchport access vlan 4\n mls qos trust cos\n");
  const map = new Map([["GigabitEthernet0/11", { target: "Te1/1/3", transform: "routed", vlan: null }]]);
  const out = convertLegacyQos(applyInterfaceMap(src, map));
  assert.deepEqual(ifaceBlock(out, "TenGigabitEthernet1/1/3"), [
    "interface TenGigabitEthernet1/1/3",
    " switchport access vlan 4",
    " auto qos trust cos",
  ]);
});

// ------------------------------------- domain name / RSA key / VTY left to template

test("source ip domain-name is not carried over (template supplies the domain name)", () => {
  const p = parse("ip name-server 10.0.0.10\nip domain-name old.corp.local\nip domain name other.local\nip domain-list a.local\n");
  assert.deepEqual(p.dns, ["ip name-server 10.0.0.10"]);
  const slots = buildBlocks({ dns: { enabled: true } }, p);
  assert.doesNotMatch(slots.flatMap((s) => s.lines).join("\n"), /domain/);
});

test("buildRsaKey emits the 2048-bit key generation command", () => {
  assert.deepEqual(buildRsaKey(), ["crypto key generate rsa modulus 2048"]);
});

test("nothing Crucible injects touches line vty (template VTY settings stay as-is)", () => {
  const sec = buildSecureAccess({ username: "netadmin", password: "Sec!", configKey: "Key1" });
  assert.ok(!sec.some((l) => /^line vty/.test(l)));
  assert.ok(!sec.some((l) => /transport input/.test(l)));
  const findings = audit(parse("hostname X\nline vty 0 4\n transport input telnet\n"));
  for (const f of findings) f.apply = true;
  const lines = remediationLines(findings);
  assert.ok(!lines.some((l) => /^line vty|transport input|access-class/.test(l)), lines.join("\n"));
  assert.ok(lines.includes("line con 0")); // console hardening is still offered
});
