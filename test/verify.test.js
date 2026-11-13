import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../public/lib/parser.js";
import { audit } from "../public/lib/hardening.js";
import { pairOutput, pairFiles, compareConfigs, applyHardening, hardenedName } from "../public/lib/verify.js";

const file = (path, text) => ({ name: path.split("/").pop(), path, text, parsed: parse(text) });

const SRC = [
  "hostname CVS-basement-sw",
  "!",
  "vlan 10",
  " name USERS",
  "vlan 20",
  " name VOICE",
  "!",
  "interface GigabitEthernet0/1",
  " description Uplink to core",
  " switchport mode trunk",
  "!",
  "interface GigabitEthernet0/2",
  " description Printer",
  " switchport access vlan 10",
  " spanning-tree portfast",
  "!",
  "interface Vlan10",
  " ip address 10.1.10.2 255.255.255.0",
  "!",
  "ip default-gateway 10.1.10.1",
  "ip http server",
  "snmp-server community public RO",
  "username admin password cisco123",
  "end",
].join("\n");

const OUT = [
  "hostname CVS-basement-sw",
  "ip domain name corp.local",
  "!",
  "vlan 10",
  " name USERS",
  "vlan 20",
  " name PHONES",
  "vlan 99",
  " name MGMT",
  "!",
  "interface TenGigabitEthernet1/1/1",
  " description Uplink to core",
  " switchport mode trunk",
  "!",
  "interface GigabitEthernet1/0/2",
  " description Printer",
  " switchport access vlan 10",
  " spanning-tree portfast",
  "!",
  "interface Vlan10",
  " ip address 10.1.10.2 255.255.255.0",
  "!",
  "ip route 0.0.0.0 0.0.0.0 10.1.10.1",
  "ip http server",
  "snmp-server community public RO",
  "username admin password cisco123",
  "end",
].join("\n");

// ------------------------------------------------------------------ pairing

test("pairing: a unique filename match wins", () => {
  const sources = [file("src/a/SW1.txt", "hostname ALPHA\n"), file("src/a/SW2.txt", "hostname BETA\n")];
  const hit = pairOutput(file("out/a/sw1.txt", "hostname SOMETHING-ELSE\n"), sources);
  assert.equal(hit.source, sources[0]);
  assert.equal(hit.by, "filename");
});

test("pairing: Crucible output named after the hostname pairs with a differently named source", () => {
  const sources = [file("src/Aspatria/Aspatria Router.txt", "hostname ASP-RT1\n"), file("src/Aspatria/Aspatria Switch.txt", "hostname ASP-SW1\n")];
  const hit = pairOutput(file("out/Aspatria/ASP-SW1.txt", "hostname ASP-SW1\n"), sources);
  assert.equal(hit.source, sources[1]);
  assert.equal(hit.by, "hostname");
});

test("pairing: an ambiguous filename is settled by the source hostname", () => {
  const sources = [file("src/SiteA/Router.txt", "hostname A-RT\n"), file("src/SiteB/Router.txt", "hostname B-RT\n")];
  const hit = pairOutput(file("edited/Router.txt", "hostname B-RT\n"), sources);
  assert.equal(hit.source, sources[1]);
  assert.equal(hit.by, "hostname");
});

test("pairing: same hostname at two sites is narrowed by the site folder; otherwise left unpaired", () => {
  const sources = [file("src/SiteA/r.txt", "hostname Router\n"), file("src/SiteB/r.txt", "hostname Router\n")];
  assert.equal(pairOutput(file("out/SiteB/Router.txt", "hostname Router\n"), sources).source, sources[1]);
  assert.equal(pairOutput(file("out/Elsewhere/Router.txt", "hostname Router\n"), sources), null);
});

test("pairFiles: renamed device stays unpaired and its source is reported unused", () => {
  const sources = [file("src/BourdonSW1.txt", "hostname BourdonSW1\n"), file("src/Other.txt", "hostname Other\n")];
  const outputs = [file("out/BourdonL3SW1.txt", "hostname BourdonL3SW1\n"), file("out/Other_hardened.txt", "hostname Other\n")];
  const { pairs, unusedSources } = pairFiles(sources, outputs);
  assert.equal(pairs[0].source, null);
  assert.equal(pairs[1].source, sources[1]); // a _hardened copy still pairs by filename
  assert.deepEqual(unusedSources, [sources[0]]);
});

// ------------------------------------------------------------------ compare

test("compare: addresses, VLANs and converted default gateway all match", () => {
  const c = compareConfigs(parse(SRC), parse(OUT));
  assert.equal(c.ok, true);
  assert.equal(c.ip.matched.length, 1);
  assert.deepEqual(c.ip.missing, []);
  assert.deepEqual(c.vlans.missing, []);
  assert.deepEqual(c.vlans.extra, [{ id: 99, name: "MGMT" }]);
  assert.deepEqual(c.vlans.renamed, [{ id: 20, from: "VOICE", to: "PHONES" }]);
  assert.equal(c.gateway.status, "match");
  assert.equal(c.gateway.converted, true); // ip default-gateway → default route
});

test("compare: interfaces remapped summary (by description; by address when an IP moved)", () => {
  const c = compareConfigs(parse(SRC), parse(OUT));
  assert.deepEqual(
    c.interfaces.remapped.map((r) => `${r.from}>${r.to}:${r.basis}`).sort(),
    ["GigabitEthernet0/1>TenGigabitEthernet1/1/1:description", "GigabitEthernet0/2>GigabitEthernet1/0/2:description"]
  );
  const moved = compareConfigs(
    parse("interface FastEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n"),
    parse("interface Vlan1\n ip address 192.168.1.1 255.255.255.0\ninterface Vlan50\n ip address 10.50.0.1 255.255.255.0\n")
  );
  assert.equal(moved.ip.ok, true);
  assert.deepEqual(moved.interfaces.remapped, [{ from: "FastEthernet0/0", to: "Vlan1", basis: "address", detail: "192.168.1.1 255.255.255.0" }]);
  assert.deepEqual(moved.ip.extra.map((a) => a.key), ["10.50.0.1 255.255.255.0"]); // extra = information only
});

test("compare: a changed address, a dropped VLAN and a different gateway are all flagged", () => {
  const bad = OUT.replace("10.1.10.2 255.255.255.0", "10.1.10.3 255.255.255.0")
    .replace("vlan 20\n name PHONES\n", "")
    .replace("0.0.0.0 0.0.0.0 10.1.10.1", "0.0.0.0 0.0.0.0 10.1.10.254");
  const c = compareConfigs(parse(SRC), parse(bad));
  assert.equal(c.ok, false);
  assert.deepEqual(c.ip.missing.map((a) => `${a.iface} ${a.key}`), ["Vlan10 10.1.10.2 255.255.255.0"]);
  assert.deepEqual(c.vlans.missing, [{ id: 20, name: "VOICE" }]);
  assert.equal(c.gateway.status, "mismatch");
  assert.equal(compareConfigs(parse(SRC), parse("hostname X\n")).gateway.status, "missing");
});

// ---------------------------------------------------------------- hardening

test("hardenedName appends _hardened before the extension", () => {
  assert.equal(hardenedName("CVS-basement-sw.txt"), "CVS-basement-sw_hardened.txt");
  assert.equal(hardenedName("core.v2.cfg"), "core.v2_hardened.cfg");
  assert.equal(hardenedName("CVS-basement-sw_hardened.txt"), "CVS-basement-sw_hardened.txt");
});

test("applyHardening: ticked fixes go in after ip domain name, the rest of the file is untouched", () => {
  const findings = audit(parse(OUT));
  findings.find((f) => f.id === "login-throttling").apply = true;
  const { content, added, removed } = applyHardening(OUT, findings);
  const lines = content.split("\n");
  const at = lines.indexOf("ip domain name corp.local");
  assert.deepEqual(lines.slice(at + 1, at + 5), ["!", "! ==== Hardening ====", "! [Medium] No login throttling", "login block-for 120 attempts 3 within 60"]);
  assert.equal(added, 1);
  assert.deepEqual(removed, []);
  // every original line is still there, in order
  const kept = lines.filter((l) => OUT.split("\n").includes(l));
  assert.ok(OUT.split("\n").every((l) => kept.includes(l)));
});

test("applyHardening: all fixes applied clears every fixable finding on re-check", () => {
  const findings = audit(parse(OUT));
  for (const f of findings) if (f.status === "missing") f.apply = true;
  const { content, removed, placeholders } = applyHardening(OUT, findings);

  // contradicting lines are gone, so the fix isn't undone further down the file
  assert.ok(removed.includes("ip http server"));
  assert.ok(removed.includes("snmp-server community public RO"));
  assert.ok(removed.includes("username admin password cisco123"));
  assert.doesNotMatch(content, /^ip http server$/m);
  assert.match(content, /^no ip http server$/m);
  assert.match(content, /^username admin secret <STRONG-SECRET>$/m);
  assert.ok(placeholders.includes("<STRONG-SECRET>"));

  // per-interface fix merged into the existing block, not a second stanza
  assert.match(content, /interface GigabitEthernet1\/0\/2\n description Printer\n switchport access vlan 10\n spanning-tree portfast\n spanning-tree bpduguard enable\n!/);
  assert.equal(content.match(/^interface GigabitEthernet1\/0\/2$/gm).length, 1);

  const after = audit(parse(content)).filter((f) => f.status === "missing");
  // What remains needs a human: advisory-only findings (nothing to inject) and
  // the syslog host, which stays open until its <SYSLOG-IP> placeholder is filled.
  assert.deepEqual(after.filter((f) => f.remediation.length).map((f) => f.id), ["logging"]);
  assert.ok(placeholders.includes("<SYSLOG-IP>"));

  // the checks that matched before still match
  assert.equal(compareConfigs(parse(SRC), parse(content)).ok, true);
});

test("applyHardening: nothing ticked is a no-op; no domain name line falls back to the end; CRLF kept", () => {
  assert.equal(applyHardening(OUT, audit(parse(OUT))).content, OUT);
  const text = "hostname X\r\nip http server\r\nend\r\n";
  const findings = audit(parse(text));
  findings.find((f) => f.id === "ip-http-server").apply = true;
  const { content } = applyHardening(text, findings);
  assert.ok(content.includes("\r\n! ==== Hardening ====\r\n! [Medium] ip http server enabled\r\nno ip http server"));
  assert.ok(!/[^\r]\n/.test(content));
});
