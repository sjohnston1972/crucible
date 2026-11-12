import { test } from "node:test";
import assert from "node:assert/strict";

import { parse, parseVlans } from "../public/lib/parser.js";
import { mergeMissingVlans } from "../public/lib/template.js";

const SRC = [
  "hostname SW9",
  "vlan internal allocation policy ascending",
  "!",
  "vlan 10",
  " name USERS",
  "!",
  "vlan 101",
  " name vlan101",
  "!",
  "vlan 200,300-302",
  "!",
  "vlan 1002",
  " name fddi-default",
  "!",
  "interface GigabitEthernet1/0/1",
  " switchport access vlan 101",
  "!",
].join("\n");

test("parser collects vlan definitions with names, expanding lists", () => {
  const p = parse(SRC);
  assert.deepEqual(
    p.vlans.map((v) => [v.id, v.name]),
    [[10, "USERS"], [101, "vlan101"], [200, null], [300, null], [301, null], [302, null], [1002, "fddi-default"]]
  );
  assert.deepEqual(p.vlans[1].block, ["vlan 101", " name vlan101"]);
});

test("parser ignores non-definition vlan commands", () => {
  const v = parseVlans(["vlan internal allocation policy ascending", "vlan access-map X 10", " action drop", "vlan configuration 10"]);
  assert.deepEqual(v.vlans, []);
});

test("missing VLANs are added after the template's last vlan block", () => {
  const tpl = ["hostname T", "!", "vlan 10", " name TEMPLATE-USERS", "vlan 20", " name DATA", "!", "interface Vlan10", " no shutdown", "!", "end"].join("\n");
  const r = mergeMissingVlans(tpl, parse(SRC));
  assert.deepEqual(r.added, [101, 200, 300, 301, 302]);
  const lines = r.content.split("\n");
  assert.deepEqual(lines.slice(4, 13), [
    "vlan 20", " name DATA",
    "vlan 101", " name vlan101",
    "vlan 200", "vlan 300", "vlan 301", "vlan 302",
    "!",
  ]);
  // template name wins for a VLAN in both; nothing duplicated
  assert.equal(r.content.match(/^vlan 10$/gm).length, 1);
  assert.match(r.content, /name TEMPLATE-USERS/);
  assert.doesNotMatch(r.content, /name USERS\b/);
  // default VLANs never added
  assert.doesNotMatch(r.content, /^vlan 1002$/m);
});

test("template list lines count as defined", () => {
  const tpl = "vlan 100-102,200\n!\nend\n";
  const r = mergeMissingVlans(tpl, parse(SRC));
  assert.deepEqual(r.added, [10, 300, 301, 302]);
});

test("template with no VLANs gets a labelled block before the first interface", () => {
  const tpl = ["hostname T", "!", "interface GigabitEthernet1/0/1", " description x", "!", "end"].join("\n");
  const r = mergeMissingVlans(tpl, parse("vlan 101\n name vlan101\n"));
  assert.deepEqual(r.content.split("\n"), [
    "hostname T", "!",
    "! ==== VLANs (from source) ====", "vlan 101", " name vlan101", "!",
    "interface GigabitEthernet1/0/1", " description x", "!", "end",
  ]);
});

test("no interfaces and no VLANs in template: block appended", () => {
  const r = mergeMissingVlans("hostname T\n", parse("vlan 101\n name vlan101\n"));
  assert.equal(r.content, "hostname T\n!\n! ==== VLANs (from source) ====\nvlan 101\n name vlan101\n");
});

test("nothing to add leaves content untouched", () => {
  const tpl = "vlan 101\n name X\n";
  const r = mergeMissingVlans(tpl, parse("vlan 101\n name vlan101\n"));
  assert.equal(r.content, tpl);
  assert.deepEqual(r.added, []);
});

test("VLANs used on ports but defined nowhere are reported, not invented", () => {
  const tpl = ["vlan 10", "!", "interface Gi1/0/1", " switchport access vlan 30", " switchport voice vlan 40", "interface Gi1/0/2", " switchport access vlan 10", "interface Gi1/0/3", " switchport access vlan 1"].join("\n");
  const r = mergeMissingVlans(tpl, parse("hostname X\n"));
  assert.deepEqual(r.undefinedUsed, [30, 40]);
  assert.equal(r.content, tpl);
});
