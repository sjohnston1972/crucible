import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../public/lib/parser.js";
import {
  DOT1X_DEFAULTS,
  normalizeSettings,
  validateSettings,
  scanDot1x,
  qualifyingPorts,
  globalLines,
  portLines,
  checkDot1x,
  changesText,
  applyDot1x,
  stripPortDot1x,
  addDot1xToOutput,
  POLICY_NAME,
  PREAUTH_ACL,
  IPDT_POLICY,
} from "../public/lib/dot1x.js";

const SET = { server1Ip: "10.1.1.10", server2Ip: "10.1.1.11", key: "S3cret" };

const SWITCH = [
  "version 17.9",
  "hostname BLD1-SW1",
  "!",
  "aaa new-model",
  "!",
  "ip domain name corp.local",
  "!",
  "interface Port-channel1",
  " switchport mode trunk",
  "!",
  "interface GigabitEthernet0/0",
  " vrf forwarding Mgmt-vrf",
  " ip address 10.0.0.5 255.255.255.0",
  "!",
  "interface GigabitEthernet1/0/1",
  " description User port",
  " switchport access vlan 10",
  " switchport mode access",
  " spanning-tree portfast",
  "!",
  "interface GigabitEthernet1/0/2",
  " description Lobby AP",
  " switchport access vlan 20",
  " switchport mode access",
  "!",
  "interface GigabitEthernet1/0/3",
  " switchport access vlan 10",
  " shutdown",
  "!",
  "interface GigabitEthernet1/0/4",
  " switchport mode access",
  " channel-group 1 mode active",
  "!",
  "interface TenGigabitEthernet1/1/1",
  " description UPLINK to core",
  " switchport mode trunk",
  "!",
  "interface Vlan10",
  " ip address 10.1.10.2 255.255.255.0",
  "!",
  "line vty 0 4",
  " transport input ssh",
  "end",
].join("\n");

const names = (list) => list.map((p) => p.normName);

// ------------------------------------------------------------------ settings

test("defaults: policy style, monitor mode, 802.1X then MAB", () => {
  assert.equal(DOT1X_DEFAULTS.style, "policy");
  assert.equal(DOT1X_DEFAULTS.mode, "monitor");
  assert.equal(DOT1X_DEFAULTS.order, "dot1x");
  assert.equal(DOT1X_DEFAULTS.hostMode, "multi-auth");
  const s = normalizeSettings({ style: "bogus", mode: "nope", authPort: "" });
  assert.equal(s.style, "policy");
  assert.equal(s.mode, "monitor");
  assert.equal(s.authPort, 1812);
});

test("validateSettings names each blank or bad required box", () => {
  const msgs = validateSettings({});
  assert.ok(msgs.some((m) => /server 1 IP is blank/.test(m)));
  assert.ok(msgs.some((m) => /Shared key is blank/.test(m)));
  assert.deepEqual(validateSettings(SET), []);
  assert.ok(validateSettings({ ...SET, server1Ip: "10.1.1.999" }).some((m) => /not an IPv4/.test(m)));
  assert.ok(validateSettings({ ...SET, criticalVlan: "5000" }).some((m) => /Critical VLAN/.test(m)));
  assert.ok(validateSettings({ ...SET, server2Ip: "10.1.1.10" }).some((m) => /same as server 1/.test(m)));
});

// --------------------------------------------------------------------- ports

test("qualifyingPorts: access ports only, skip words by description", () => {
  const q = qualifyingPorts(parse(SWITCH), { ...SET, skipWords: "AP, uplink" });
  assert.deepEqual(names(q.ports), ["GigabitEthernet1/0/1", "GigabitEthernet1/0/3"]);
  assert.deepEqual(names(q.skipped), ["GigabitEthernet1/0/2"]);
  assert.equal(q.skipped[0].word, "ap");
  // no skip words: the AP port qualifies; trunk, routed, channel member never do
  assert.deepEqual(names(qualifyingPorts(parse(SWITCH), SET).ports), [
    "GigabitEthernet1/0/1",
    "GigabitEthernet1/0/2",
    "GigabitEthernet1/0/3",
  ]);
});

// ---------------------------------------------------------------- generators

test("global block: policy style carries the control policy, classic does not", () => {
  const pol = globalLines(SET);
  assert.ok(pol.includes("aaa new-model"));
  assert.ok(pol.includes(" address ipv4 10.1.1.10 auth-port 1812 acct-port 1813"));
  assert.ok(pol.includes(" key S3cret"));
  assert.ok(pol.includes("aaa authentication dot1x default group ISE-RADIUS"));
  assert.ok(pol.includes("aaa accounting identity default start-stop group ISE-RADIUS"));
  assert.ok(pol.includes(" client 10.1.1.11 server-key S3cret"));
  assert.ok(pol.includes("dot1x system-auth-control"));
  assert.ok(pol.includes(`policy-map type control subscriber ${POLICY_NAME}`));
  assert.ok(!pol.some((l) => /CRITICAL/.test(l)), "no critical VLAN set, so no critical templates");
  assert.ok(!pol.some((l) => l.includes(PREAUTH_ACL)), "monitor mode has no pre-auth ACL");

  const cls = globalLines({ ...SET, style: "classic" });
  assert.ok(cls.includes("aaa accounting dot1x default start-stop group ISE-RADIUS"));
  assert.ok(!cls.some((l) => /policy-map|class-map|service-template/.test(l)));
});

test("global block: optional settings appear only when set", () => {
  const g = globalLines({ ...SET, sourceInterface: "Vlan10", probeUser: "probe", coaKey: "CoA1", criticalVlan: "100", mode: "low" });
  assert.ok(g.includes(" ip radius source-interface Vlan10"));
  assert.ok(g.includes(" automate-tester username probe ignore-acct-port probe-on"));
  assert.ok(g.includes(" client 10.1.1.10 server-key CoA1"));
  assert.ok(g.includes(`ip access-list extended ${PREAUTH_ACL}`));
  assert.ok(g.includes("service-template CRITICAL_AUTH_ACCESS"));
  assert.ok(g.includes(" vlan 100"));
  assert.ok(g.includes("   20 activate service-template CRITICAL_AUTH_ACCESS"));

  const off = globalLines({ ...SET, coa: false, server2Ip: "" });
  assert.ok(!off.includes("aaa server radius dynamic-author"));
  assert.ok(!off.some((l) => /ISE-2|source-interface|automate-tester/.test(l)));
});

test("control policy follows the chosen order", () => {
  const at = (lines, head) => lines[lines.indexOf(head) + 2];
  const d = globalLines(SET);
  assert.equal(at(d, " event session-started match-all"), "   10 authenticate using dot1x priority 10");
  const m = globalLines({ ...SET, order: "mab" });
  assert.equal(at(m, " event session-started match-all"), "   10 authenticate using mab priority 20");
  assert.ok(m.includes("  5 class MAB_FAILED do-until-failure"));
});

test("port block: policy style, three modes", () => {
  const mon = portLines(SET);
  assert.deepEqual(mon, [
    "access-session host-mode multi-auth",
    "access-session port-control auto",
    "authentication periodic",
    "authentication timer reauthenticate server",
    "mab",
    "dot1x pae authenticator",
    "dot1x timeout tx-period 10",
    `device-tracking attach-policy ${IPDT_POLICY}`,
    `service-policy type control subscriber ${POLICY_NAME}`,
  ]);
  const closed = portLines({ ...SET, mode: "closed" });
  assert.equal(closed[1], "access-session closed");
  assert.ok(!mon.includes("access-session closed"));
  assert.ok(portLines({ ...SET, mode: "low" }).includes(`ip access-group ${PREAUTH_ACL} in`));
});

test("port block: classic style, three modes and options", () => {
  const mon = portLines({ ...SET, style: "classic", criticalVlan: "100", order: "mab", hostMode: "multi-domain", txPeriod: 7 });
  assert.deepEqual(mon, [
    "authentication host-mode multi-domain",
    "authentication order mab dot1x",
    "authentication priority dot1x mab",
    "authentication port-control auto",
    "authentication open",
    "authentication periodic",
    "authentication timer reauthenticate server",
    "authentication event server dead action authorize vlan 100",
    "authentication event server dead action authorize voice",
    "authentication event server alive action reinitialize",
    "mab",
    "dot1x pae authenticator",
    "dot1x timeout tx-period 7",
    `device-tracking attach-policy ${IPDT_POLICY}`,
  ]);
  const closed = portLines({ ...SET, style: "classic", mode: "closed", reauth: false });
  assert.ok(!closed.includes("authentication open"));
  assert.ok(!closed.includes("authentication periodic"));
  assert.ok(portLines({ ...SET, style: "classic", mode: "low" }).includes("authentication open"));
});

// ---------------------------------------------------------------------- scan

test("scanDot1x: style detection and the Catalyst 9000 version guard", () => {
  assert.equal(scanDot1x(parse(SWITCH)).style, null);
  assert.equal(scanDot1x(parse(SWITCH)).supported, true);
  const classic = SWITCH.replace(" spanning-tree portfast", " authentication port-control auto\n spanning-tree portfast");
  assert.equal(scanDot1x(parse(classic)).style, "classic");
  const policy = SWITCH.replace(" spanning-tree portfast", " access-session port-control auto");
  assert.equal(scanDot1x(parse(policy)).style, "policy");

  const old = parse(SWITCH.replace("version 17.9", "version 15.2"));
  assert.equal(scanDot1x(old).supported, false);
  const c = checkDot1x(old, SET);
  assert.equal(c.supported, false);
  assert.deepEqual(c.global, []);
  assert.match(changesText(c, { hostname: "x", settings: SET }), /No changes generated/);
  // no version line at all: treated as a Catalyst 9000
  assert.equal(scanDot1x(parse(SWITCH.replace("version 17.9\n", ""))).supported, true);
});

// --------------------------------------------------------------------- check

test("check: a switch with no 802.1X needs everything except aaa new-model", () => {
  const c = checkDot1x(parse(SWITCH), { ...SET, skipWords: "AP" });
  assert.equal(c.supported, true);
  assert.equal(c.conflict, false);
  assert.equal(c.complete, false);
  assert.equal(c.items.find((i) => i.id === "aaa").state, "present");
  assert.ok(c.items.filter((i) => i.id !== "aaa").every((i) => i.state === "missing"));
  assert.deepEqual(names(c.ports), ["GigabitEthernet1/0/1", "GigabitEthernet1/0/3"]);
  assert.ok(c.ports.every((p) => p.state === "missing" && p.add.length === 9));
  assert.deepEqual(c.counts, { globalsPresent: 1, globalsTotal: c.items.length, portsDone: 0, portsTotal: 2 });
  assert.ok(!c.global.includes("aaa new-model"));
});

test("check: opts.ports limits the ports that are checked", () => {
  const c = checkDot1x(parse(SWITCH), SET, { ports: new Set(["GigabitEthernet1/0/3"]) });
  assert.deepEqual(names(c.ports), ["GigabitEthernet1/0/3"]);
});

test("check: aaa new-model missing is generated with a warning", () => {
  const c = checkDot1x(parse(SWITCH.replace("aaa new-model\n", "")), SET);
  assert.equal(c.global[0], "aaa new-model");
  assert.ok(c.warnings.some((w) => /changes how administrators log in/.test(w)));
  assert.match(changesText(c, { hostname: "BLD1-SW1", settings: SET }), /! WARNING: aaa new-model is not enabled/);
});

test("check: an existing server at the same IP is matched by function and its name reused", () => {
  const cfg = SWITCH.replace(
    "ip domain name corp.local",
    [
      "radius server PSN-A",
      " address ipv4 10.1.1.10 auth-port 1812 acct-port 1813",
      " key 7 0822455D0A16",
      "!",
      "aaa group server radius CORP-ISE",
      " server name PSN-A",
      "!",
      "aaa authentication dot1x default group CORP-ISE",
      "ip domain name corp.local",
    ].join("\n")
  );
  const c = checkDot1x(parse(cfg), SET);
  const item = (id) => c.items.find((i) => i.id === id);
  assert.equal(item("server:10.1.1.10").state, "present");
  assert.equal(item("server:10.1.1.11").state, "missing");
  // no parallel server or group is created
  assert.ok(!c.global.includes("radius server ISE-1"));
  assert.ok(!c.global.includes("aaa group server radius ISE-RADIUS"));
  // the existing group gains only the missing member
  const at = c.global.indexOf("aaa group server radius CORP-ISE");
  assert.ok(at >= 0);
  assert.equal(c.global[at + 1], " server name ISE-2");
  assert.equal(item("authn").state, "present");
  assert.ok(c.global.includes("aaa authorization network default group CORP-ISE"));
});

test("check: a value that is there but different is reported, never emitted", () => {
  const cfg = SWITCH.replace(
    "ip domain name corp.local",
    [
      "radius server ISE-1",
      " address ipv4 10.9.9.9 auth-port 1812 acct-port 1813",
      "!",
      "aaa authentication dot1x default group radius",
      "radius-server deadtime 60",
      "ip domain name corp.local",
    ].join("\n")
  );
  const c = checkDot1x(parse(cfg), SET);
  const item = (id) => c.items.find((i) => i.id === id);
  assert.equal(item("server:10.1.1.10").state, "differs");
  assert.match(item("server:10.1.1.10").detail, /ISE-1 is 10\.9\.9\.9, settings say 10\.1\.1\.10/);
  assert.equal(item("authn").state, "differs");
  assert.ok(!c.global.includes("radius server ISE-1"));
  assert.ok(!c.global.some((l) => /^aaa authentication dot1x/.test(l)));
  assert.ok(!c.global.includes("radius-server deadtime 15"));
  assert.match(changesText(c, { hostname: "x", settings: SET }), /! NOT CHANGED: RADIUS server 10\.1\.1\.10/);
});

test("check: port lines are compared one by one; a different single value is not overwritten", () => {
  const cfg = SWITCH.replace(
    " spanning-tree portfast",
    [
      " access-session host-mode single-host",
      " access-session port-control auto",
      " mab",
      " service-policy type control subscriber OTHER-POLICY",
    ].join("\n")
  );
  const c = checkDot1x(parse(cfg), SET);
  const p = c.ports.find((x) => x.normName === "GigabitEthernet1/0/1");
  assert.equal(p.state, "partial");
  assert.ok(!p.add.some((l) => /host-mode|service-policy|port-control/.test(l)));
  assert.ok(!p.add.includes("mab"));
  assert.ok(p.add.includes("dot1x pae authenticator"));
  assert.equal(p.differs.length, 2);
  assert.ok(p.differs.some((d) => /OTHER-POLICY/.test(d)));
});

test("check: a port already closed is never opened", () => {
  const closedPolicy = SWITCH.replace(" spanning-tree portfast", " access-session closed\n access-session port-control auto");
  const p1 = checkDot1x(parse(closedPolicy), SET).ports[0];
  assert.ok(p1.differs.some((d) => /left closed/.test(d)));
  assert.deepEqual(p1.remove, []);

  const closedClassic = SWITCH.replace(" spanning-tree portfast", " authentication port-control auto");
  const p2 = checkDot1x(parse(closedClassic), { ...SET, style: "classic" }).ports[0];
  assert.ok(!p2.add.includes("authentication open"));
  assert.ok(p2.differs.some((d) => /left closed/.test(d)));
});

test("check: selecting Closed moves open ports to closed, with a warning", () => {
  const openClassic = SWITCH.replace(" spanning-tree portfast", " authentication port-control auto\n authentication open");
  const c = checkDot1x(parse(openClassic), { ...SET, style: "classic", mode: "closed" });
  assert.deepEqual(c.ports[0].remove, ["authentication open"]);
  assert.ok(c.warnings.some((w) => /1 port already running 802\.1X in open mode will move to CLOSED/.test(w)));
  assert.match(changesText(c, { hostname: "x", settings: { ...SET, style: "classic", mode: "closed" } }), /\n no authentication open\n/);
  const full = applyDot1x(openClassic, c).content;
  assert.ok(!/\n authentication open\n/.test(full));
});

test("check: ports in the other style are a conflict — no port lines, no control policy", () => {
  const classic = SWITCH.replace(" spanning-tree portfast", " authentication port-control auto\n authentication open");
  const c = checkDot1x(parse(classic), SET); // settings: policy
  assert.equal(c.conflict, true);
  assert.equal(c.complete, false);
  assert.ok(c.ports.every((p) => p.state === "conflict" && !p.add.length));
  assert.ok(!c.global.some((l) => /policy-map|class-map|device-tracking/.test(l)));
  assert.ok(c.global.includes("dot1x system-auth-control"), "shared globals are still generated");
  assert.ok(c.warnings.some((w) => /cannot be mixed/.test(w)));
});

// -------------------------------------------------------------- changes file

test("changesText: comments and config lines only; nothing missing says so", () => {
  const c = checkDot1x(parse(SWITCH), SET);
  const text = changesText(c, { hostname: "BLD1-SW1", settings: SET });
  assert.match(text, /^! 802\.1X changes for BLD1-SW1\n! Generated by Crucible - style: Policy-based \(IBNS 2\.0\), mode: Monitor\n/);
  assert.match(text, /\ninterface GigabitEthernet1\/0\/1\n access-session host-mode multi-auth\n/);
  assert.ok(text.includes("\nradius server ISE-1\n"));

  const done = applyDot1x(SWITCH, c).content;
  const again = checkDot1x(parse(done), SET);
  assert.match(changesText(again, { hostname: "BLD1-SW1", settings: SET }), /! No changes needed\.\n$/);
});

// --------------------------------------------------------------------- merge

for (const style of ["policy", "classic"]) {
  for (const mode of ["monitor", "low", "closed"]) {
    test(`applyDot1x is idempotent (${style}, ${mode})`, () => {
      const s = { ...SET, style, mode, criticalVlan: "100", sourceInterface: "Vlan10", probeUser: "probe" };
      const c1 = checkDot1x(parse(SWITCH), s);
      const r1 = applyDot1x(SWITCH, c1);
      assert.ok(r1.added > 0);
      const c2 = checkDot1x(parse(r1.content), s);
      assert.equal(c2.complete, true, JSON.stringify(c2.items.filter((i) => i.state !== "present")) + JSON.stringify(c2.ports));
      assert.deepEqual(c2.global, []);
      assert.equal(c2.counts.portsDone, c2.counts.portsTotal);
      const r2 = applyDot1x(r1.content, c2);
      assert.equal(r2.content, r1.content);
      assert.equal(r2.added, 0);
    });
  }
}

test("applyDot1x: globals go after ip domain name, port lines into the existing blocks", () => {
  const c = checkDot1x(parse(SWITCH), SET);
  const lines = applyDot1x(SWITCH, c).content.split("\n");
  const dom = lines.indexOf("ip domain name corp.local");
  assert.equal(lines[dom + 1], "!");
  assert.equal(lines[dom + 2], "! ==== 802.1X ====");
  assert.ok(lines.indexOf(`policy-map type control subscriber ${POLICY_NAME}`) < lines.indexOf("interface GigabitEthernet1/0/1"));
  const at = lines.indexOf("interface GigabitEthernet1/0/1");
  const block = lines.slice(at, lines.indexOf("!", at));
  assert.equal(block[4], " spanning-tree portfast");
  assert.equal(block[block.length - 1], ` service-policy type control subscriber ${POLICY_NAME}`);
  // untouched ports and everything else stay as they were
  assert.ok(lines.includes(" description UPLINK to core"));
  assert.equal(lines.filter((l) => l === "interface GigabitEthernet1/0/1").length, 1);
  assert.equal(lines[lines.length - 1], "end");
});

test("applyDot1x: no domain name line — globals go before the first interface", () => {
  const cfg = SWITCH.replace("ip domain name corp.local\n!\n", "");
  const lines = applyDot1x(cfg, checkDot1x(parse(cfg), SET)).content.split("\n");
  assert.ok(lines.indexOf("! ==== 802.1X ====") < lines.indexOf("interface Port-channel1"));
  assert.ok(lines.indexOf("dot1x system-auth-control") < lines.indexOf("interface Port-channel1"));
});

test("applyDot1x: aaa new-model further down the file is repeated ahead of the AAA lines", () => {
  const cfg = SWITCH.replace("aaa new-model\n!\n", "").replace("line vty 0 4", "aaa new-model\n!\nline vty 0 4");
  const lines = applyDot1x(cfg, checkDot1x(parse(cfg), SET)).content.split("\n");
  const head = lines.indexOf("! ==== 802.1X ====");
  assert.equal(lines[head + 1], "aaa new-model");
});

test("applyDot1x keeps CRLF line endings", () => {
  const crlf = SWITCH.replace(/\n/g, "\r\n");
  const out = applyDot1x(crlf, checkDot1x(parse(crlf), SET)).content;
  assert.ok(out.includes("dot1x system-auth-control\r\n"));
  assert.ok(!/[^\r]\n/.test(out), "no bare LF");
});

// ----------------------------------------------------------------- main flow

const OLD_2960_OUTPUT = [
  "version 15.2",
  "hostname OLD-SW",
  "ip domain name corp.local",
  "!",
  "interface GigabitEthernet1/0/1",
  " switchport access vlan 10",
  " switchport mode access",
  " authentication host-mode multi-domain",
  " authentication order mab dot1x",
  " authentication port-control auto",
  " mab",
  " dot1x pae authenticator",
  " dot1x timeout tx-period 3",
  " spanning-tree portfast",
  "!",
  "interface GigabitEthernet1/0/2",
  " switchport mode trunk",
  "!",
  "end",
].join("\n");

test("stripPortDot1x removes per-port 802.1X lines of either style and nothing else", () => {
  const r = stripPortDot1x(OLD_2960_OUTPUT);
  assert.deepEqual(r.ports, ["GigabitEthernet1/0/1"]);
  assert.ok(!/authentication|dot1x|\n mab\n/.test(r.content));
  assert.ok(r.content.includes(" switchport access vlan 10\n switchport mode access\n spanning-tree portfast"));
  assert.deepEqual(stripPortDot1x(SWITCH), { content: SWITCH, ports: [] });
});

test("addDot1xToOutput: old classic port lines are replaced with the selected style on access ports only", () => {
  const r = addDot1xToOutput(OLD_2960_OUTPUT, SET);
  const out = r.content;
  assert.equal(r.ports, 1);
  assert.ok(r.warnings.some((w) => /replaced the old 802\.1X lines on 1 port/.test(w)));
  assert.ok(!/authentication (host-mode|order|port-control)/.test(out));
  assert.ok(!out.includes("tx-period 3"));
  assert.ok(out.includes("aaa new-model"));
  assert.ok(out.includes(`policy-map type control subscriber ${POLICY_NAME}`));
  const lines = out.split("\n");
  const at = lines.indexOf("interface GigabitEthernet1/0/1");
  const block = lines.slice(at, lines.indexOf("!", at));
  assert.ok(block.includes(" access-session port-control auto"));
  assert.ok(block.includes(` service-policy type control subscriber ${POLICY_NAME}`));
  const trunk = lines.indexOf("interface GigabitEthernet1/0/2");
  assert.deepEqual(lines.slice(trunk, trunk + 3), ["interface GigabitEthernet1/0/2", " switchport mode trunk", "!"]);
  // the result is complete: a check of it finds nothing left to add
  assert.equal(checkDot1x(parse(out), SET, { ignoreVersion: true }).complete, true);
});
