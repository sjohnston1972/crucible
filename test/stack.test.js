import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { parse, normalizeInterfaceName } from "../public/lib/parser.js";
import { applyInterfaceMap, detectInterfaceMapConflicts } from "../public/lib/template.js";
import {
  TARGET_MODELS,
  targetModel,
  targetPorts,
  autoMapInterfaces,
  sourceStack,
  stackSize,
  stackProvisionLines,
  stripProvisionLines,
  stackWarnings,
  downlinkCount,
  downlinkName,
  modelUplinks,
} from "../public/lib/targets.js";

const cfg = (names, extra = "") => parse(extra + names.map((n) => `interface ${n}\n switchport mode access\n!`).join("\n"));
const range = (prefix, from, to) => Array.from({ length: to - from + 1 }, (_, i) => `${prefix}${from + i}`);
const targets = (map) => Object.fromEntries([...map].map(([k, v]) => [k, v.target]));
const sample = (f) => parse(readFileSync(new URL("../public/sample-data/" + f, import.meta.url), "utf8"));

// ------------------------------------------------------------------ parser

test("parser: switch N provision lines are collected as stack members", () => {
  const p = parse("switch 1 provision ws-c3750x-24p\nswitch 2 provision ws-c3750x-48p\n!\ninterface Vlan1\n");
  assert.deepEqual(p.stackMembers, [
    { member: 1, model: "ws-c3750x-24p" },
    { member: 2, model: "ws-c3750x-48p" },
  ]);
  assert.deepEqual(parse("hostname X\n").stackMembers, []);
});

test("parser: newer multigigabit / 25G / 40G / 100G port names normalise", () => {
  assert.equal(normalizeInterfaceName("Tw1/0/1"), "TwoGigabitEthernet1/0/1");
  assert.equal(normalizeInterfaceName("Fi1/0/2"), "FiveGigabitEthernet1/0/2");
  assert.equal(normalizeInterfaceName("five1/0/2"), "FiveGigabitEthernet1/0/2");
  assert.equal(normalizeInterfaceName("Twe1/1/1"), "TwentyFiveGigE1/1/1");
  assert.equal(normalizeInterfaceName("twenty1/1/1"), "TwentyFiveGigE1/1/1");
  assert.equal(normalizeInterfaceName("Te1/1/1"), "TenGigabitEthernet1/1/1");
  assert.equal(normalizeInterfaceName("Fo1/1/1"), "FortyGigabitEthernet1/1/1");
  assert.equal(normalizeInterfaceName("Hu1/0/49"), "HundredGigE1/0/49");
  assert.equal(normalizeInterfaceName("Ap1/0/1"), "AppGigabitEthernet1/0/1");
  assert.equal(normalizeInterfaceName("gi 0/1"), "GigabitEthernet0/1");
});

// ------------------------------------------------------------ source stack

test("sourceStack: members come from provision lines and from port names (Gi0/1, Gi2/1, Gi3/0/1)", () => {
  const p = cfg(["GigabitEthernet0/1", "GigabitEthernet2/1", "GigabitEthernet3/0/1", "Vlan1"], "switch 4 provision ws-c3750x-24p\n");
  const s = sourceStack(p);
  assert.deepEqual(s.members, [1, 2, 3, 4]);
  assert.equal(s.provisioned.get(4), "ws-c3750x-24p");
  assert.deepEqual(sourceStack(parse("hostname R1\ninterface Loopback0\n")).members, []);
});

test("sourceStack: the real stacked samples report their member counts", () => {
  assert.deepEqual(sourceStack(sample("cmb/CMB-TUK-SWT02_sh run.txt")).members.length >= 2, true);
  assert.deepEqual(sourceStack(sample("bourdon/BourdonSW1.txt")).members.length >= 2, true);
});

// ------------------------------------------------------------- model table

test("every model is well formed", () => {
  const ids = new Set();
  for (const m of TARGET_MODELS) {
    assert.ok(!ids.has(m.id), `duplicate id ${m.id}`);
    ids.add(m.id);
    assert.ok(m.family && m.label, m.id);
    assert.ok(m.maxStack >= 1, m.id);
    assert.ok(downlinkCount(m) >= 1, m.id);
    // downlink ranges are contiguous from 1 with no overlap
    let next = 1;
    for (const r of [...m.downlinks].sort((a, b) => a.from - b.from)) {
      assert.equal(r.from, next, `${m.id}: downlink ranges must be contiguous`);
      next = r.to + 1;
    }
    // every port name is unique and in running-config form, for every uplink module
    for (const mod of m.modules && m.modules.length ? m.modules : [null]) {
      const ports = targetPorts(m, { members: m.maxStack, module: mod && mod.id });
      assert.equal(new Set(ports).size, ports.length, `${m.id}: duplicate port names`);
      for (const n of ports) {
        assert.match(n, /^(GigabitEthernet|TwoGigabitEthernet|FiveGigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE)\d+\/\d+\/\d+$/, `${m.id}: ${n}`);
        assert.equal(normalizeInterfaceName(n), n, `${m.id}: ${n}`);
      }
      assert.ok(modelUplinks(m, mod && mod.id).length >= 1 || !mod, m.id);
    }
    for (const v of m.variants || []) assert.match(v, /^c9[0-9a-z-]+$/, `${m.id}: variant ${v}`);
  }
});

test("targetPorts lists every member of the stack being built", () => {
  const m = targetModel("c9200l-24-4x");
  assert.equal(targetPorts(m).length, 28);
  const three = targetPorts(m, { members: 3 });
  assert.equal(three.length, 84);
  assert.ok(three.includes("GigabitEthernet3/0/24") && three.includes("TenGigabitEthernet2/1/4"));
  assert.equal(targetPorts(m, { members: 99 }).length, 28 * m.maxStack); // clamped to what the model stacks
  assert.equal(targetPorts(targetModel("c9200cx-12p-2x2g"), { members: 4 }).length, 16); // does not stack
});

test("stackSize clamps to 1..maxStack", () => {
  const m = targetModel("c9200l-48-4x");
  assert.equal(stackSize(m, 0), 1);
  assert.equal(stackSize(m, "3"), 3);
  assert.equal(stackSize(m, 20), m.maxStack);
  assert.equal(stackSize(m, "abc"), 1);
});

// ---------------------------------------------------------------- auto map

test("auto map: Gi0/1 → member 1, Gi2/1 → member 2, three-part names keep their member", () => {
  const p = cfg(["GigabitEthernet0/1", "GigabitEthernet2/1", "FastEthernet3/0/7"]);
  const t = targets(autoMapInterfaces(p, targetModel("c9200l-48-4x")));
  // with one or two ports per member there is nothing to treat as an uplink
  assert.equal(t["GigabitEthernet0/1"], "GigabitEthernet1/0/1");
  assert.equal(t["GigabitEthernet2/1"], "GigabitEthernet2/0/1");
  assert.equal(t["FastEthernet3/0/7"], "GigabitEthernet3/0/7");
});

test("auto map: members beyond the stack being built are left unmapped", () => {
  const p = cfg([...range("FastEthernet1/0/", 1, 8), ...range("FastEthernet2/0/", 1, 8), ...range("FastEthernet3/0/", 1, 8)]);
  const t = targets(autoMapInterfaces(p, targetModel("c9200l-24-4x"), { members: 2 }));
  assert.equal(t["FastEthernet1/0/1"], "GigabitEthernet1/0/1");
  assert.equal(t["FastEthernet2/0/1"], "GigabitEthernet2/0/1");
  assert.ok(!Object.keys(t).some((k) => k.startsWith("FastEthernet3/")));
});

test("auto map: access ports take the destination's port type at that position (multigigabit panels)", () => {
  const mgig = TARGET_MODELS.find((m) => m.downlinks.length > 1);
  assert.ok(mgig, "expected at least one model whose port type changes across the front panel");
  const n = downlinkCount(mgig);
  const p = cfg(range("GigabitEthernet0/", 1, n));
  const t = targets(autoMapInterfaces(p, mgig, { members: 1 }));
  const first = mgig.downlinks[0];
  const last = mgig.downlinks[mgig.downlinks.length - 1];
  assert.equal(t[`GigabitEthernet0/${first.from}`], `${first.type}1/0/${first.from}`);
  // the last few source ports are taken as uplinks; check one that stays a downlink in the last range
  assert.equal(downlinkName(mgig, 1, last.from), `${last.type}1/0/${last.from}`);
  assert.equal(downlinkName(mgig, 2, n), `${last.type}2/0/${n}`);
  assert.equal(downlinkName(mgig, 1, n + 1), null);
});

test("auto map: a source uplink already on a destination uplink name keeps it; configured uplinks go first", () => {
  // 9300-style source: every uplink type is present, only Te1/1/1 and Te1/1/2 are configured
  const text =
    range("GigabitEthernet1/0/", 1, 4).map((n) => `interface ${n}\n switchport mode access\n!`).join("\n") +
    "\n" +
    range("GigabitEthernet1/1/", 1, 4).map((n) => `interface ${n}\n!`).join("\n") +
    "\ninterface TenGigabitEthernet1/1/1\n switchport mode trunk\n!\ninterface TenGigabitEthernet1/1/2\n switchport mode trunk\n!\n";
  const map = autoMapInterfaces(parse(text), targetModel("c9200l-24-4x"), { members: 1 });
  const t = targets(map);
  assert.equal(t["TenGigabitEthernet1/1/1"], undefined); // same name on the destination — not remapped
  assert.equal(t["TenGigabitEthernet1/1/2"], undefined);
  // the unconfigured Gi1/1/x placeholders only get what is left (Te1/1/3-4), never the configured ports' slots
  assert.deepEqual(
    Object.values(t).filter((v) => /\/1\/\d+$/.test(v)).sort(),
    ["TenGigabitEthernet1/1/3", "TenGigabitEthernet1/1/4"]
  );
});

test("auto map: no model ever produces conflicts or duplicate interfaces on the real samples", () => {
  for (const f of ["paisley/Paisley L3 Switch.txt", "cmb/CMB-TUK-SWT02_sh run.txt", "bourdon/BourdonSW1.txt"]) {
    const p = sample(f);
    for (const model of TARGET_MODELS) {
      for (const mod of model.modules && model.modules.length ? model.modules : [null]) {
        const map = autoMapInterfaces(p, model, { module: mod && mod.id });
        const hard = detectInterfaceMapConflicts(p, map, { label: f }).filter((w) => w.hard);
        assert.deepEqual(hard, [], `${f} → ${model.id}`);
        const names = applyInterfaceMap(p, map).interfaces.map((i) => i.normName);
        assert.equal(new Set(names).size, names.length, `duplicate interface after remap: ${f} → ${model.id}`);
        const allowed = new Set(targetPorts(model, { members: model.maxStack, module: mod && mod.id }));
        for (const m of map.values()) assert.ok(allowed.has(m.target), `${f} → ${model.id}: ${m.target} is not a port on the model`);
      }
    }
  }
});

// ------------------------------------------------------------ provision lines

test("stackProvisionLines: one line per member, nothing without an exact model keyword", () => {
  const m = targetModel("c9200l-48-4x");
  assert.deepEqual(stackProvisionLines(m, 3, "c9200l-48p-4x"), [
    "switch 1 provision c9200l-48p-4x",
    "switch 2 provision c9200l-48p-4x",
    "switch 3 provision c9200l-48p-4x",
  ]);
  assert.deepEqual(stackProvisionLines(m, 3, ""), []);
  assert.deepEqual(stackProvisionLines(null, 3, "x"), []);
  assert.equal(stackProvisionLines(targetModel("c9200cx-12p-2x2g"), 4, "c9200cx-12p-2x2g").length, 1);
});

test("stripProvisionLines removes only the template's switch N provision lines", () => {
  assert.equal(
    stripProvisionLines("hostname T\nswitch 1 provision ws-c3750x-24p\nswitch 2 provision ws-c3750x-24p\ninterface Gi1/0/1\n switch 1 provision nope\nend"),
    "hostname T\ninterface Gi1/0/1\n switch 1 provision nope\nend"
  );
});

// ------------------------------------------------------------------ warnings

test("stackWarnings: members that don't fit, and a stack with no exact model chosen", () => {
  const p = cfg([...range("FastEthernet1/0/", 1, 4), ...range("FastEthernet2/0/", 1, 4), ...range("FastEthernet3/0/", 1, 4)]);
  const stackable = targetModel("c9200l-24-4x");

  const fits = stackWarnings(p, stackable, { members: 3, keyword: "c9200l-24p-4x", label: "SW1" });
  assert.deepEqual(fits, []);

  const small = stackWarnings(p, stackable, { members: 2, keyword: "c9200l-24p-4x", label: "SW1" });
  assert.equal(small.length, 1);
  assert.match(small[0], /^SW1: source uses stack member 3 but the new stack is set to 2 members/);

  const noKeyword = stackWarnings(p, stackable, { members: 3, keyword: "", label: "SW1" });
  assert.equal(noKeyword.length, 1);
  assert.match(noKeyword[0], /no "switch N provision" lines were written/);

  const single = stackWarnings(p, targetModel("c9200cx-12p-2x2g"), { members: 3, label: "SW1" });
  assert.equal(single.length, 1);
  assert.match(single[0], /source uses stack members 2, 3 but C9200CX-12P-2X2G does not stack/);

  assert.deepEqual(stackWarnings(cfg(["GigabitEthernet0/1"]), stackable, { members: 1 }), []);
});
