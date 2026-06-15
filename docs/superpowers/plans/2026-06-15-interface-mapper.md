# Interface Mapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-device interface-mapping mechanism that remaps each source interface to a target hardware name (with optional routed→SVI transform), suppresses colliding interfaces so the mapped source wins, and flags hard conflicts.

**Architecture:** A pure pre-pass `applyInterfaceMap(parsed, map)` in `public/lib/template.js` returns a transformed clone of the parsed config; every emit/preview path consumes the transform. A pure `detectInterfaceMapConflicts` feeds the existing warnings flow. `public/app.js` gains a per-device `ifaceMap` state field, a translation of the per-interface selection through the map, and a collapsible mapper UI in `renderUnit`.

**Tech Stack:** Vanilla ES modules, `node --test`, no framework.

---

## File structure

- `public/lib/template.js` — add `applyInterfaceMap`, `detectInterfaceMapConflicts`, and internal helpers `makeSyntheticIface`, `renameIface`. Pure, Node- and browser-importable.
- `test/template.test.js` — add unit tests for both new functions.
- `public/app.js` — add `ifaceMap` to `defaultDeviceCfg`; translate selections + transform parsed in the build/save/preview paths; add conflict warnings; render the mapper subsection in `renderUnit`.

The parsed interface object shape (from `parser.js`) is:
`{ name, normName, block, text, description, shutdown, vrf, ipAddresses, hasIp, switchportLines, stpLines, helperAddresses, channelGroup }`.
`block` is the array of raw lines, `block[0]` being `interface <rawname>`; children are indented.

---

### Task 1: `applyInterfaceMap` — rename + suppress

**Files:**
- Modify: `public/lib/template.js`
- Test: `test/template.test.js`

- [ ] **Step 1: Write the failing tests**

Add to `test/template.test.js` (import `applyInterfaceMap` in the existing import block from `../public/lib/template.js`):

```js
import { applyInterfaceMap } from "../public/lib/template.js"; // add to existing import list

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
  // router intf renamed to Gi1/0/24, switch's own Gi1/0/24 suppressed
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test`
Expected: FAIL — `applyInterfaceMap is not a function` / `is not exported`.

- [ ] **Step 3: Implement `applyInterfaceMap` (rename + suppress) and helpers**

Add to `public/lib/template.js`:

```js
// --------------------------------------------------------- interface remap

function renameIface(f, target) {
  const block = f.block.slice();
  if (block.length) block[0] = "interface " + target;
  return { ...f, name: target, normName: target, block, text: block.join("\n") };
}

function makeSyntheticIface(name, block) {
  const ipAddresses = block.filter((l) => /^\s*ip address\s/.test(l)).map((l) => l.trim());
  return {
    name, normName: name, block, text: block.join("\n"),
    description: null, shutdown: false, vrf: null,
    ipAddresses, hasIp: ipAddresses.length > 0,
    switchportLines: block.filter((l) => /^\s*switchport\b/.test(l)).map((l) => l.trim()),
    stpLines: [], helperAddresses: [], channelGroup: null,
  };
}

/**
 * Apply a per-device interface remap, returning a transformed CLONE of parsed.
 * map: Map(srcNormName -> { target, transform: "routed"|"svi", vlan }).
 * Empty target / self-map entries are no-ops. The input parsed is never mutated.
 */
export function applyInterfaceMap(parsed, map) {
  if (!map || map.size === 0) return parsed;

  const remap = new Map(); // srcNormName -> { target, transform, vlan }
  for (const [normName, m] of map) {
    if (!m || !m.target || !m.target.trim()) continue;
    const target = normalizeInterfaceName(m.target.trim());
    if (target === normName) continue;
    remap.set(normName, { transform: m.transform || "routed", vlan: m.vlan, target });
  }
  if (remap.size === 0) return parsed;

  const suppressed = new Set([...remap.values()].map((m) => m.target));
  const out = [];
  const synthSvis = [];

  for (const f of parsed.interfaces || []) {
    const m = remap.get(f.normName);
    if (!m) {
      if (!suppressed.has(f.normName)) out.push(f); // dropped if replaced by a mapped source
      continue;
    }
    if (m.transform === "svi" && m.vlan) {
      const vlanName = normalizeInterfaceName("Vlan" + m.vlan);
      const l3 = f.ipAddresses.slice();
      let svi = synthSvis.find((s) => s.normName === vlanName) || out.find((s) => s.normName === vlanName);
      if (svi) {
        svi.block.push(...l3.map((l) => " " + l));
        svi.ipAddresses.push(...l3);
        svi.hasIp = svi.hasIp || l3.length > 0;
        svi.text = svi.block.join("\n");
      } else {
        synthSvis.push(makeSyntheticIface(vlanName, ["interface " + vlanName, ...l3.map((l) => " " + l)]));
      }
      out.push(makeSyntheticIface(m.target, [
        "interface " + m.target, " switchport mode access", " switchport access vlan " + m.vlan,
      ]));
    } else {
      out.push(renameIface(f, m.target));
    }
  }
  return { ...parsed, interfaces: [...out, ...synthSvis] };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test`
Expected: PASS (all template tests, including the two new ones).

- [ ] **Step 5: Commit**

```bash
git add public/lib/template.js test/template.test.js
git commit -m "feat(template): applyInterfaceMap rename + collision suppression"
```

---

### Task 2: `applyInterfaceMap` — SVI synthesis

**Files:**
- Test: `test/template.test.js` (function already implemented in Task 1; this verifies the SVI branch)

- [ ] **Step 1: Write the failing tests**

```js
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
```

- [ ] **Step 2: Run the tests**

Run: `npm test`
Expected: PASS (SVI branch implemented in Task 1).

- [ ] **Step 3: Commit**

```bash
git add test/template.test.js
git commit -m "test(template): SVI synthesis coverage for applyInterfaceMap"
```

---

### Task 3: `detectInterfaceMapConflicts`

**Files:**
- Modify: `public/lib/template.js`
- Test: `test/template.test.js`

- [ ] **Step 1: Write the failing tests**

```js
import { detectInterfaceMapConflicts } from "../public/lib/template.js"; // add to import list

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test`
Expected: FAIL — `detectInterfaceMapConflicts is not exported`.

- [ ] **Step 3: Implement `detectInterfaceMapConflicts`**

Add to `public/lib/template.js`:

```js
/**
 * Validate an interface remap. Returns [{ hard, message }].
 * hard = blocks generation; soft = informational warning.
 * opts.label: device label for messages.
 * opts.selectedTargets: Set of target normNames the user ticked for collection.
 */
export function detectInterfaceMapConflicts(parsed, map, opts = {}) {
  const warnings = [];
  if (!map || map.size === 0) return warnings;
  const label = opts.label || "device";
  const selected = opts.selectedTargets instanceof Set ? opts.selectedTargets : new Set();

  const byTarget = new Map(); // target -> [srcNormName]
  for (const [normName, m] of map) {
    if (!m || !m.target || !m.target.trim()) continue;
    const target = normalizeInterfaceName(m.target.trim());
    if (target === normName) continue;
    if (m.transform === "svi" && (m.vlan == null || !String(m.vlan).trim())) {
      warnings.push({ hard: true, message: `${label}: ${normName} mapped as SVI but no VLAN given — set a VLAN.` });
    }
    if (!byTarget.has(target)) byTarget.set(target, []);
    byTarget.get(target).push(normName);
  }

  for (const [target, sources] of byTarget) {
    if (sources.length > 1) {
      warnings.push({ hard: true, message: `${label}: ${sources.join(" and ")} both map to ${target} — pick distinct targets.` });
    } else if (selected.has(target) && (parsed.interfaces || []).some((f) => f.normName === target)) {
      warnings.push({ hard: false, message: `${label}: ${target} config replaced by mapped ${sources[0]}.` });
    }
  }
  return warnings;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add public/lib/template.js test/template.test.js
git commit -m "feat(template): detectInterfaceMapConflicts"
```

---

### Task 4: Wire transform + selection translation + conflicts into `public/app.js`

**Files:**
- Modify: `public/app.js`

- [ ] **Step 1: Add `ifaceMap` to `defaultDeviceCfg`**

In `defaultDeviceCfg(p)` (around app.js:226), add after `ifaceSel`:

```js
    ifaceMap: new Map(), // normName -> { target, transform: "routed"|"svi", vlan }
```

- [ ] **Step 2: Import the new functions**

Add `applyInterfaceMap` and `detectInterfaceMapConflicts` to the existing import from the template module at the top of `app.js` (the block importing `buildBlocks`).

- [ ] **Step 3: Add a selection-translation helper**

Add near `unitConfig` (app.js:249). This rewrites the per-interface selection names so the slot lookup matches the transformed parsed; SVI selections fan out to the access port + the Vlan SVI:

```js
/** Translate per-interface selections through the device's ifaceMap. */
function mappedSelections(selected, ifaceMap) {
  if (!ifaceMap || ifaceMap.size === 0) return selected;
  const out = [];
  const seen = new Set();
  const push = (name, mode) => { const k = name + "::" + mode; if (!seen.has(k)) { seen.add(k); out.push({ name, mode }); } };
  for (const sel of selected) {
    const m = ifaceMap.get(sel.name);
    if (!m || !m.target || !m.target.trim()) { push(sel.name, sel.mode); continue; }
    const target = normalizeInterfaceName(m.target.trim());
    if (target === sel.name) { push(sel.name, sel.mode); continue; }
    if (m.transform === "svi" && m.vlan) {
      push(target, "full");
      push(normalizeInterfaceName("Vlan" + m.vlan), "full");
    } else {
      push(target, sel.mode);
    }
  }
  return out;
}
```

Note: `normalizeInterfaceName` must be importable in `app.js` — add it to the parser import (check the existing `import ... from "./lib/parser.js"`; if absent, add it).

- [ ] **Step 4: Apply translation in `unitConfig`**

In `unitConfig` (app.js:252), wrap the computed `interfaces` list:

```js
  const interfaces = d.interfacesAll.enabled
    ? []
    : mappedSelections(
        [...d.ifaceSel.entries()].filter(([, v]) => v.checked).map(([name, v]) => ({ name, mode: v.mode })),
        d.ifaceMap
      );
```

- [ ] **Step 5: Transform parsed at the build/save call site**

At the `buildBlocks` call (app.js:870), pass the transformed parsed:

```js
    const tparsed = applyInterfaceMap(unit.parsed, deviceCfg(unit).ifaceMap);
    const slots = buildBlocks(ucfg, tparsed, {
```

(Use `tparsed` for any subsequent use of `unit.parsed` inside that same emit block, e.g. naming/preview built from the same parsed.)

- [ ] **Step 6: Add conflict detection to the two warning flows**

In `rebuildUnits` (after the `detectStpConflicts` line, app.js:570) and again per-unit in the save flow (`allWarnings`, near app.js:921), add:

```js
    const d = deviceCfg(unit); // (rebuildUnits: use the unit being built)
    const selTargets = new Set([...d.ifaceSel.entries()].filter(([, v]) => v.checked).map(([n]) => n));
    for (const w of detectInterfaceMapConflicts(unit.parsed, d.ifaceMap, { label: unit.id, selectedTargets: selTargets })) {
      warnings.push(w.message); // rebuildUnits: warnings;  save flow: allWarnings
      if (w.hard) { /* save flow only */ }
    }
```

In the **save flow**, when a hard conflict exists for a unit, skip writing that unit (mirror the VTP/secure-access skip at app.js:904/914): set a `skip` flag before the write and `continue`.

- [ ] **Step 7: Run the full suite + node smoke check**

Run: `npm test`
Expected: PASS (no regressions).

Run a smoke check that the wiring imports resolve (node parses the module graph via the test import of template.js; app.js is browser-only, so verify by grepping that `applyInterfaceMap`/`mappedSelections` are referenced and `normalizeInterfaceName` is imported).

- [ ] **Step 8: Commit**

```bash
git add public/app.js
git commit -m "feat(app): wire interface remap transform, selection translation, and conflicts"
```

---

### Task 5: Mapper UI subsection in `renderUnit`

**Files:**
- Modify: `public/app.js`
- Modify: `public/styles.css` (if a stylesheet exists; otherwise reuse `.unit-sub` classes)

- [ ] **Step 1: Insert the subsection markup**

In `renderUnit`, between the Interfaces subsection `</details>` (app.js:1098) and the Routing & services `<details>` (app.js:1099), insert a new collapsible built from `ifaces` and `d.ifaceMap`. Build a sibling-port datalist from units in the same site:

```js
    // Interface mapping subsection
    (() => {
      const siblingPorts = [...new Set(
        state.units.filter((u) => u.site.path === unit.site.path && u.id !== unit.id)
          .flatMap((u) => (u.parsed.interfaces || []).map((f) => f.normName))
      )].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      const knownVlans = [...new Set(
        (p.interfaces || []).map((f) => (f.normName.match(/^Vlan(\d+)$/i) || [])[1]).filter(Boolean)
      )];
      const mapped = ifaces.filter((f) => d.ifaceMap.get(f.normName)?.target?.trim()).length;
      const dlId = `ports-${unit.id}`;
      const vlId = `vlans-${unit.id}`;
      const rows = ifaces.map((f) => {
        const m = d.ifaceMap.get(f.normName) || { target: "", transform: "routed", vlan: "" };
        const isSvi = m.transform === "svi";
        return (
          `<div class="ifmap-row" data-name="${escapeHtml(f.normName)}">` +
          `<span class="ifmap-src">${escapeHtml(f.normName)}</span><span class="ifmap-arrow">→</span>` +
          `<input class="ifmap-target" list="${dlId}" placeholder="(keep name)" value="${escapeHtml(m.target || "")}" />` +
          `<label class="ifmap-mode"><input type="radio" name="ifmode-${unit.id}-${escapeHtml(f.normName)}" value="routed"${isSvi ? "" : " checked"} /> routed</label>` +
          `<label class="ifmap-mode"><input type="radio" name="ifmode-${unit.id}-${escapeHtml(f.normName)}" value="svi"${isSvi ? " checked" : ""} /> SVI</label>` +
          `<input class="ifmap-vlan${isSvi ? "" : " hidden"}" placeholder="VLAN" list="${vlId}" value="${escapeHtml(m.vlan || "")}" />` +
          `</div>`
        );
      }).join("");
      return (
        `<details class="unit-sub"><summary class="unit-sub-head"><strong>Interface mapping</strong> ` +
        `<span class="muted small">${mapped} remapped</span></summary>` +
        `<p class="muted small sub-desc">Remap a source interface to a target hardware port. Blank = keep. A mapped target replaces any colliding port on this device.</p>` +
        `<div class="ifmap-rows">${rows}</div>` +
        `<datalist id="${dlId}">${siblingPorts.map((n) => `<option value="${escapeHtml(n)}">`).join("")}</datalist>` +
        `<datalist id="${vlId}">${knownVlans.map((n) => `<option value="${escapeHtml(n)}">`).join("")}</datalist>` +
        `</details>`
      );
    })() +
```

- [ ] **Step 2: Wire the change handlers**

After the card's interfaces handlers are wired (near app.js:1124+), add:

```js
  card.querySelectorAll(".ifmap-row").forEach((row) => {
    const name = row.dataset.name;
    const get = () => d.ifaceMap.get(name) || { target: "", transform: "routed", vlan: "" };
    const set = (patch) => { d.ifaceMap.set(name, { ...get(), ...patch }); refreshTagMap(); };
    const targetIn = row.querySelector(".ifmap-target");
    const vlanIn = row.querySelector(".ifmap-vlan");
    targetIn.addEventListener("input", () => set({ target: targetIn.value }));
    vlanIn.addEventListener("input", () => set({ vlan: vlanIn.value }));
    row.querySelectorAll(`input[type=radio]`).forEach((r) =>
      r.addEventListener("change", () => {
        const svi = row.querySelector(`input[value=svi]`).checked;
        vlanIn.classList.toggle("hidden", !svi);
        set({ transform: svi ? "svi" : "routed" });
      })
    );
  });
```

- [ ] **Step 3: Add styles**

If `public/styles.css` exists, add a focused rule set; otherwise rely on existing `.unit-sub`/`.hidden`:

```css
.ifmap-row { display: grid; grid-template-columns: 1fr auto 1.4fr auto auto auto; gap: .4rem; align-items: center; margin: .25rem 0; }
.ifmap-arrow { opacity: .6; }
.ifmap-target, .ifmap-vlan { font: inherit; padding: .15rem .3rem; }
.ifmap-vlan { max-width: 6rem; }
```

(Confirm `.hidden { display: none }` already exists — it is used by the rename rows at app.js:1459. If so, reuse it.)

- [ ] **Step 4: Manual verification in the app**

Run: `npm run dev`, scan a folder containing a router + switch site, expand a device, open **Interface mapping**, map a router interface onto a switch port, then **view config** / generate and confirm:
- the mapped interface emits under the target name;
- the colliding switch port no longer emits its own block;
- SVI mode emits `interface Vlan<n>` + a switchported access port;
- duplicate targets / SVI-without-VLAN surface a blocking warning.

- [ ] **Step 5: Commit**

```bash
git add public/app.js public/styles.css
git commit -m "feat(ui): per-device Interface mapping subsection"
```

---

### Task 6: Integration test — transformed parsed flows through `buildBlocks`

**Files:**
- Test: `test/template.test.js`

- [ ] **Step 1: Write the test**

```js
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
```

- [ ] **Step 2: Run it**

Run: `npm test`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add test/template.test.js
git commit -m "test(template): integration — renamed interface emits via buildBlocks"
```

---

## Self-review

- **Spec coverage:** data model (Task 4), `applyInterfaceMap` rename/suppress/SVI (Tasks 1–2), `detectInterfaceMapConflicts` (Task 3), build/save wiring + selection translation (Task 4), UI subsection between Interfaces and Routing & services (Task 5), integration (Task 6). Duplicate-source-`normName` edge case is resolved by the mapper renaming one (covered by suppression logic).
- **Type consistency:** `ifaceMap` entries are `{ target, transform, vlan }` everywhere; `detectInterfaceMapConflicts` returns `{ hard, message }`; transformed objects carry `normName`/`block`/`ipAddresses` matching the parser shape consumed by `buildBlocks`.
- **Out of scope (per spec):** IP/subnet overlap, static-route conflicts, duplicate VLAN-name detection, auto-suggested mappings.
