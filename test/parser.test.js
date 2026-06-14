import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { parse, normalizeInterfaceName, extractBlock } from "../public/lib/parser.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const bourdon = readFileSync(join(__dirname, "..", "public", "sample-data", "bourdon", "BourdonSW1.txt"), "utf8");

// --------------------------------------------------------- name normalisation

test("normalizeInterfaceName: short forms expand to canonical", () => {
  assert.equal(normalizeInterfaceName("Gi0/1"), "GigabitEthernet0/1");
  assert.equal(normalizeInterfaceName("Te1/0/1"), "TenGigabitEthernet1/0/1");
  assert.equal(normalizeInterfaceName("Fa0/24"), "FastEthernet0/24");
  assert.equal(normalizeInterfaceName("Vl10"), "Vlan10");
  assert.equal(normalizeInterfaceName("Po1"), "Port-channel1");
  assert.equal(normalizeInterfaceName("Lo0"), "Loopback0");
});

test("normalizeInterfaceName: canonical names are idempotent", () => {
  assert.equal(normalizeInterfaceName("GigabitEthernet0/1"), "GigabitEthernet0/1");
  assert.equal(normalizeInterfaceName("Vlan1"), "Vlan1");
  assert.equal(normalizeInterfaceName("TenGigabitEthernet1/1/1"), "TenGigabitEthernet1/1/1");
});

// ------------------------------------------------------------------ hostname

test("hostname: first hostname line wins", () => {
  assert.equal(parse("hostname Core1\nhostname Other\n").hostname, "Core1");
  assert.equal(parse(bourdon).hostname, "BourdonSW1");
});

// ----------------------------------------------------------- block extraction

test("extractBlock: stops at ! terminator", () => {
  const lines = ["interface Gi0/1", " description x", " no shutdown", "!", "hostname Z"];
  const { block, endIdx } = extractBlock(lines, 0);
  assert.deepEqual(block, ["interface Gi0/1", " description x", " no shutdown"]);
  assert.equal(endIdx, 2);
});

test("extractBlock: stops at next non-indented command", () => {
  const lines = ["router ospf 1", " network 10.0.0.0", "ip route 0.0.0.0 0.0.0.0 1.1.1.1"];
  const { block } = extractBlock(lines, 0);
  assert.deepEqual(block, ["router ospf 1", " network 10.0.0.0"]);
});

// ------------------------------------------------------------------ interfaces

const IFACE_SAMPLE = `hostname T
interface GigabitEthernet1/0/1
 description Access port
 switchport access vlan 20
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface Vlan10
 description SVI
 ip address 10.1.10.1 255.255.255.0
 ip address 10.1.10.2 255.255.255.0 secondary
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 shutdown
!
`;

test("interface: full block, description, switchport, per-port STP captured", () => {
  const p = parse(IFACE_SAMPLE);
  const gi = p.interfaces.find((f) => f.normName === "GigabitEthernet1/0/1");
  assert.ok(gi);
  assert.equal(gi.description, "Access port");
  assert.equal(gi.switchportLines.length, 2);
  assert.deepEqual(gi.stpLines, ["spanning-tree portfast", "spanning-tree bpduguard enable"]);
  assert.equal(gi.hasIp, false);
});

test("interface: IP-only extraction includes secondary", () => {
  const p = parse(IFACE_SAMPLE);
  const svi = p.interfaces.find((f) => f.normName === "Vlan10");
  assert.equal(svi.hasIp, true);
  assert.deepEqual(svi.ipAddresses, [
    "ip address 10.1.10.1 255.255.255.0",
    "ip address 10.1.10.2 255.255.255.0 secondary",
  ]);
});

test("interface: channel-group (port-channel membership) captured", () => {
  const p = parse(
    "interface Te1/1/1\n description Uplink\n switchport mode trunk\n channel-group 2 mode on\n!\ninterface Gi1/0/1\n switchport mode access\n!\n"
  );
  const te = p.interfaces.find((f) => f.normName === "TenGigabitEthernet1/1/1");
  assert.equal(te.channelGroup, 2);
  const gi = p.interfaces.find((f) => f.normName === "GigabitEthernet1/0/1");
  assert.equal(gi.channelGroup, null);
});

test("interface: vrf forwarding + shutdown captured", () => {
  const p = parse(IFACE_SAMPLE);
  const mg = p.interfaces.find((f) => f.normName === "GigabitEthernet0/0");
  assert.equal(mg.vrf, "Mgmt-vrf");
  assert.equal(mg.shutdown, true);
});

// ------------------------------------------------------------------ routing

test("static + default route: ip route default sets defaultGateway", () => {
  const p = parse("ip route 0.0.0.0 0.0.0.0 192.168.1.1\nip route 10.0.0.0 255.0.0.0 10.1.1.1\n");
  assert.equal(p.staticRoutes.length, 2);
  assert.deepEqual(p.defaultGateway, {
    nextHop: "192.168.1.1",
    source: "default-route",
    raw: "ip route 0.0.0.0 0.0.0.0 192.168.1.1",
  });
});

test("default gateway: L2 ip default-gateway captured for modernisation", () => {
  const p = parse(bourdon);
  assert.equal(p.defaultGateway.source, "default-gateway");
  assert.equal(p.defaultGateway.nextHop, "192.168.1.1");
});

test("routing protocol block captured with children", () => {
  const p = parse("router ospf 10\n router-id 1.1.1.1\n network 10.0.0.0 0.0.0.255 area 0\n!\n");
  assert.equal(p.protocols.length, 1);
  assert.equal(p.protocols[0].type, "ospf");
  assert.equal(p.protocols[0].id, "10");
  assert.ok(p.protocols[0].lines.includes("router-id 1.1.1.1"));
});

// ------------------------------------------------------------------ VRF

test("VRF: modern definition with rd/route-target and interface binding", () => {
  const cfg = `vrf definition RED
 rd 65000:1
 route-target export 65000:1
 route-target import 65000:1
!
interface Gi0/1
 vrf forwarding RED
 ip address 10.0.0.1 255.255.255.0
!
ip route vrf RED 0.0.0.0 0.0.0.0 10.0.0.254
`;
  const p = parse(cfg);
  assert.equal(p.vrfs.length, 1);
  const red = p.vrfs[0];
  assert.equal(red.name, "RED");
  assert.equal(red.rd, "65000:1");
  assert.equal(red.routeTargets.length, 2);
  assert.deepEqual(red.interfaces, ["GigabitEthernet0/1"]);
  assert.equal(red.routes.length, 1);
});

// ------------------------------------------------------------------ STP

test("STP: global mode + extend system-id (Bourdon = pvst)", () => {
  const p = parse(bourdon);
  assert.equal(p.spanningTree.mode, "pvst");
  assert.equal(p.spanningTree.extendSystemId, true);
});

test("STP: per-vlan priority/root parsed", () => {
  const p = parse(
    "spanning-tree vlan 1,10,20 priority 4096\nspanning-tree vlan 30 root primary\n"
  );
  const [a, b] = p.spanningTree.vlanConfig;
  assert.equal(a.vlans, "1,10,20");
  assert.equal(a.priority, 4096);
  assert.equal(b.vlans, "30");
  assert.equal(b.root, "primary");
});

test("STP: MST configuration indented block parsed", () => {
  const cfg = `spanning-tree mode mst
spanning-tree mst configuration
 name REGION1
 revision 5
 instance 1 vlan 10-20
 instance 2 vlan 30,40
!
spanning-tree mst 1 priority 4096
`;
  const p = parse(cfg);
  assert.equal(p.spanningTree.mode, "mst");
  assert.equal(p.spanningTree.mstConfig.name, "REGION1");
  assert.equal(p.spanningTree.mstConfig.revision, 5);
  assert.equal(p.spanningTree.mstConfig.instances.length, 2);
  assert.deepEqual(p.spanningTree.mstConfig.instances[0], { id: 1, vlans: "10-20" });
  assert.equal(p.spanningTree.mstConfig.priorities[0].instance, 1);
});

// ------------------------------------------------------------------ DHCP

test("DHCP: pools, excluded, helper-address", () => {
  const cfg = `ip dhcp excluded-address 10.1.10.1 10.1.10.10
ip dhcp pool DATA
 network 10.1.10.0 255.255.255.0
 default-router 10.1.10.1
 dns-server 10.1.20.10
 domain-name corp.local
 lease 7
!
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
 ip helper-address 10.1.20.50
!
`;
  const p = parse(cfg);
  assert.equal(p.excludedAddresses.length, 1);
  assert.equal(p.dhcpPools.length, 1);
  const pool = p.dhcpPools[0];
  assert.equal(pool.name, "DATA");
  assert.equal(pool.network, "10.1.10.0 255.255.255.0");
  assert.equal(pool.defaultRouter, "10.1.10.1");
  assert.deepEqual(p.helperAddresses, [{ interface: "Vlan10", ip: "10.1.20.50" }]);
});

// ------------------------------------------------------------------ robustness

test("management services scanned: SNMP / TACACS+ / NTP", () => {
  const p = parse(bourdon);
  assert.ok(p.snmp.length > 0, "snmp-server lines");
  assert.ok(p.tacacs.length > 0, "tacacs block");
  assert.ok(p.ntp.length > 0, "ntp lines");
  assert.ok(p.snmp.every((l) => /^snmp-server/.test(l)));
});

test("management capture from inline sample", () => {
  const p = parse(
    "snmp-server community ro RO\nlogging host 10.0.0.1\nntp server 10.0.0.2\ntacacs server X\n address ipv4 10.0.0.3\n!\n"
  );
  assert.equal(p.snmp.length, 1);
  assert.equal(p.logging.length, 1);
  assert.equal(p.ntp.length, 1);
  assert.ok(p.tacacs.some((l) => /tacacs server X/.test(l)));
  assert.ok(p.tacacs.some((l) => /address ipv4 10\.0\.0\.3/.test(l)));
});

test("CRLF and trailing CLI echo handled", () => {
  const p = parse("Switch#sh run\r\nBuilding configuration...\r\nhostname CRLFbox\r\n!\r\n");
  assert.equal(p.hostname, "CRLFbox");
});

test("empty / null input does not throw", () => {
  assert.equal(parse("").hostname, null);
  assert.equal(parse(null).interfaces.length, 0);
});

test("Bourdon: realistic interface counts and management SVI", () => {
  const p = parse(bourdon);
  assert.ok(p.interfaces.length > 100, "expected many interfaces");
  const v1 = p.interfaces.find((f) => f.normName === "Vlan1");
  assert.ok(v1.hasIp);
  assert.ok(v1.ipAddresses[0].includes("192.168.1.70"));
  // access port with portfast + bpduguard
  const acc = p.interfaces.find((f) => f.normName === "GigabitEthernet1/0/1");
  assert.ok(acc.stpLines.includes("spanning-tree portfast"));
  assert.ok(acc.stpLines.includes("spanning-tree bpduguard enable"));
});
