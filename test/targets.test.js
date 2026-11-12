import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { parse } from "../public/lib/parser.js";
import { applyInterfaceMap, detectInterfaceMapConflicts } from "../public/lib/template.js";
import { TARGET_MODELS, targetModel, targetPorts, autoMapInterfaces } from "../public/lib/targets.js";

const cfg = (names) => parse(names.map((n) => `interface ${n}\n switchport mode access\n!`).join("\n"));
const range = (prefix, from, to) => Array.from({ length: to - from + 1 }, (_, i) => `${prefix}${from + i}`);
const targets = (map) => Object.fromEntries([...map].map(([k, v]) => [k, v.target]));

test("three destination models are offered", () => {
  assert.deepEqual(TARGET_MODELS.map((m) => m.id), ["c9200cx-12p-2x2g", "c9200l-24-4x", "c9200l-48-4x"]);
  assert.equal(targetModel("nope"), null);
});

test("9200CX: Gi0/1-10 keep their number, Gi0/11-12 go to Te1/1/3-4", () => {
  const p = cfg([...range("GigabitEthernet0/", 1, 12), "Vlan1", "GigabitEthernet0/0"]);
  const t = targets(autoMapInterfaces(p, targetModel("c9200cx-12p-2x2g")));
  for (let n = 1; n <= 10; n++) assert.equal(t[`GigabitEthernet0/${n}`], `GigabitEthernet1/0/${n}`);
  assert.equal(t["GigabitEthernet0/11"], "TenGigabitEthernet1/1/3");
  assert.equal(t["GigabitEthernet0/12"], "TenGigabitEthernet1/1/4");
  assert.equal(Object.keys(t).length, 12); // Vlan1 and the Gi0/0 management port are not mapped
});

test("9200L-24: Fa access ports + Gi uplinks (mixed-speed front panel)", () => {
  const p = cfg([...range("FastEthernet0/", 1, 24), "GigabitEthernet0/1", "GigabitEthernet0/2"]);
  const t = targets(autoMapInterfaces(p, targetModel("c9200l-24-4x")));
  assert.equal(t["FastEthernet0/1"], "GigabitEthernet1/0/1");
  assert.equal(t["FastEthernet0/24"], "GigabitEthernet1/0/24");
  assert.equal(t["GigabitEthernet0/1"], "TenGigabitEthernet1/1/1");
  assert.equal(t["GigabitEthernet0/2"], "TenGigabitEthernet1/1/2");
});

test("9200L-24: Gi0/1-28 → last four become the 10G uplinks", () => {
  const t = targets(autoMapInterfaces(cfg(range("GigabitEthernet0/", 1, 28)), targetModel("c9200l-24-4x")));
  assert.equal(t["GigabitEthernet0/24"], "GigabitEthernet1/0/24");
  assert.deepEqual(
    range("GigabitEthernet0/", 25, 28).map((n) => t[n]),
    range("TenGigabitEthernet1/1/", 1, 4)
  );
});

test("stack members are preserved on a stackable model; uplink-module ports are the uplinks", () => {
  const p = cfg([
    ...range("GigabitEthernet1/0/", 1, 3), "TenGigabitEthernet1/1/1",
    ...range("GigabitEthernet2/0/", 1, 3), "TenGigabitEthernet2/1/1",
  ]);
  const t = targets(autoMapInterfaces(p, targetModel("c9200l-48-4x")));
  assert.deepEqual(t, {}); // already on target names — nothing to remap
  const legacy = cfg([...range("FastEthernet2/0/", 1, 2), "GigabitEthernet2/0/1"]);
  assert.deepEqual(targets(autoMapInterfaces(legacy, targetModel("c9200l-48-4x"))), {
    "FastEthernet2/0/1": "GigabitEthernet2/0/1",
    "FastEthernet2/0/2": "GigabitEthernet2/0/2",
    "GigabitEthernet2/0/1": "TenGigabitEthernet2/1/1",
  });
});

test("ports that don't fit are left unmapped", () => {
  // 48-port source onto the 12-port CX: 13-46 have nowhere to go; last 2 are the uplinks.
  const t = targets(autoMapInterfaces(cfg(range("GigabitEthernet0/", 1, 48)), targetModel("c9200cx-12p-2x2g")));
  assert.equal(t["GigabitEthernet0/12"], "GigabitEthernet1/0/12");
  assert.equal(t["GigabitEthernet0/13"], undefined);
  assert.equal(t["GigabitEthernet0/48"], "TenGigabitEthernet1/1/4");
  // second stack member on a non-stackable model
  const s = targets(autoMapInterfaces(cfg(["FastEthernet2/0/1", "FastEthernet2/0/2", "FastEthernet2/0/3"]), targetModel("c9200cx-12p-2x2g")));
  assert.deepEqual(s, {});
});

test("auto map never produces conflicts and applies cleanly on the real samples", () => {
  for (const f of ["paisley/Paisley L3 Switch.txt", "cmb/CMB-TUK-SWT02_sh run.txt", "bourdon/BourdonSW1.txt"]) {
    const p = parse(readFileSync(new URL("../public/sample-data/" + f, import.meta.url), "utf8"));
    for (const model of TARGET_MODELS) {
      const map = autoMapInterfaces(p, model);
      const hard = detectInterfaceMapConflicts(p, map, { label: f }).filter((w) => w.hard);
      assert.deepEqual(hard, [], `${f} → ${model.id}`);
      const names = applyInterfaceMap(p, map).interfaces.map((i) => i.normName);
      assert.equal(new Set(names).size, names.length, `duplicate interface after remap: ${f} → ${model.id}`);
    }
  }
});

test("targetPorts lists downlinks then uplinks", () => {
  const ports = targetPorts(targetModel("c9200cx-12p-2x2g"));
  assert.equal(ports.length, 16);
  assert.equal(ports[0], "GigabitEthernet1/0/1");
  assert.deepEqual(ports.slice(-2), ["TenGigabitEthernet1/1/3", "TenGigabitEthernet1/1/4"]);
});
