# Interface Mapper — Design

**Date:** 2026-06-15
**Status:** Approved (pending written-spec review)

## Problem

The merge pipeline (`mergeParsed` in `public/app.js`) blindly concatenates the
interfaces, routes, protocols, VRFs, and DHCP data of every source device into a
single merged unit. It performs **no** interface conflict detection. Only
spanning-tree intent is checked (`detectStpConflicts`), and that only produces
non-blocking warnings.

Concretely: when a router and a switch are merged into one Layer-3 switch, the
router's routed interfaces and the switch's physical ports collide. Real
migrations need the router's interface (its L3 intent) to land on a specific
physical switch port — and the switch's own config for that port must not
overwrite it. There is currently no mechanism to express that mapping.

## Goal

A per-device **Interface mapping** mechanism that lets the user remap each source
interface to a target hardware interface name, with an optional routed→SVI
transformation, and that suppresses any colliding interface on the same device so
the mapped (source) interface wins. The router→switch merge is the primary use
case, but the mapper is a general interface-rename tool available on **every**
device regardless of merge candidacy.

## Decisions (from brainstorming)

- **Mapper scope:** general "source interface → target hardware name" remap, on
  every device card. Merge is the special case where the target is a sibling
  switch port.
- **Target input:** free-text field with a datalist of sibling-device ports in
  the same site (covers both rename-to-new-hardware and merge-onto-switch).
- **Depth:** rename + carry config verbatim + suppress colliding interface, PLUS
  a per-row `routed | SVI` toggle. SVI converts a routed interface into an
  `interface Vlan<n>` + a switchported access port (VLAN picker required).
- **Unmapped interfaces:** carried over verbatim; in a merge, unmapped *router*
  interfaces additionally raise a confirm-intentional warning (existing
  carry-over behaviour, now flagged).
- **Placement:** a new collapsible `<details class="unit-sub">` between the
  Interfaces and Routing & services subsections in `renderUnit`.
- **Architecture:** Approach B — a pure pre-pass `applyInterfaceMap(parsed, map)`
  that returns a transformed clone of `parsed`, consumed by every downstream
  step (buildBlocks, buildTagMap, redact, pills) for consistency.

## Data model

Add one field to `defaultDeviceCfg(p)` (`public/app.js`):

```js
ifaceMap: new Map(), // normName -> { target: string, transform: "routed"|"svi", vlan: string|null }
```

- Keyed by the source interface `normName`, matching `ifaceSel`.
- Only holds interfaces the user actually remapped. An absent entry or an empty
  `target` means **keep the name** (no-op).
- `transform` defaults to `"routed"` (carry block verbatim). `"svi"` requires a
  non-empty `vlan`.
- Persists per-unit in `state.deviceCfg`, surviving re-renders, exactly like
  `ifaceSel`.

## The transform — `applyInterfaceMap(parsed, ifaceMap)`

A pure function (in `public/lib/template.js`, next to the other emit-adjacent
transforms). Returns a shallow-cloned `parsed`: clone the `interfaces` array and
each interface object that is modified; leave unrelated arrays shared. The cached
parse in `state` is never mutated.

Behaviour:

1. **Rename** — for each mapped interface with a non-empty `target`, set its
   emitted name to `normalizeInterfaceName(target)`. For `routed`, the block is
   carried verbatim under the new name.
2. **Suppress collisions** — if a mapped `target` equals another interface's
   `normName` on the same device, drop that other interface. The mapped source
   wins. This implements the router→switch "exclude from being overwritten by
   the switch part."
3. **SVI synthesis** — for `transform: "svi"`, move the source interface's L3
   lines (`ip address …`, plus `standby`/`vrrp`/`ip helper-address`) onto a
   synthesized `interface Vlan<vlan>`; the target physical port becomes
   `switchport mode access` + `switchport access vlan <vlan>`. If
   `interface Vlan<vlan>` already exists on the device, merge the L3 lines into
   it rather than duplicating the SVI.

Wiring point: the build path computes `const tp = applyInterfaceMap(unit.parsed,
d.ifaceMap)` once and substitutes `tp` wherever `unit.parsed` currently flows for
emit and preview.

## Conflict detection — `detectInterfaceMapConflicts(unit, ifaceMap)`

Runs beside `detectStpConflicts` in the `rebuildUnits` warnings flow and in the
save-time `allWarnings` flow.

- **Duplicate target (hard, blocks):** two source interfaces map to the same
  `target` — `"<unit>: Gi0/0/1 and Gi0/0/2 both map to Gi1/0/24 — pick distinct
  targets."`
- **SVI without VLAN (hard, blocks):** `transform: "svi"` with empty `vlan`.
- **Target overwrites a selected sibling interface (soft, warns):** the
  suppressed collision target was itself ticked for collection —
  `"<unit>: switch Gi1/0/24 config replaced by mapped router Gi0/0/1."`

"Blocks" uses the existing skip-at-write gate (mirrors the VTP / secure-access
incomplete-unit handling): the warning renders and the affected unit is skipped
during output.

## UI — new subsection in `renderUnit`

Inserted between the Interfaces `</details>` and the Routing & services
`<details>`:

```
> Interface mapping        (N remapped)
   Gi0/0/1  ->  [ Gi1/0/24________ v ]   ( * routed   o SVI )
   Gi0/0/0  ->  [ (keep name)______ v ]   ( * routed   o SVI )
   ... SVI selected -> row expands:        VLAN [ 60 v ]
```

- Collapsible `<details class="unit-sub">`, matching existing subsections;
  summary shows the remapped count.
- One row per source interface, using the same sorted interface list as the
  Interfaces grid.
- Target `<input>` bound to a `<datalist>` of sibling-device port `normName`s in
  the same site (units sharing `unit.site.path`).
- `routed | SVI` radio per row; SVI reveals a VLAN `<input>` + datalist of VLAN
  IDs already known on the device/site.
- Change handlers write into `d.ifaceMap` and call `refreshTagMap()` (same
  pattern as the interface tiles), so preview and pills update live.

## Edge cases

- **Duplicate source `normName` on a merged unit** (router and switch both have
  e.g. `Gi0/0/1`): the pre-existing collision that breaks `normName`-keyed maps.
  In scope: `applyInterfaceMap` and the mapper UI key colliding rows by an
  index-disambiguated key so both are addressable, and the mapper is the
  resolution path (rename one). This is the one place that touches existing
  merge behaviour.
- **Blank target** → no-op (keep name).
- **Self-map** (target equals own `normName`) → no-op, no false conflict.
- **Target matching nothing** → plain rename (new-hardware case), no warning.

## Testing (TDD)

Pure functions, no DOM:

- `applyInterfaceMap`:
  - rename-only → block carried verbatim under the new name;
  - collision → sibling suppressed, mapped source present;
  - SVI → `interface Vlan<n>` synthesized with moved L3 lines + target port
    switchported;
  - SVI into existing VLAN → merged, not duplicated;
  - blank / self / no-match targets → no-ops.
- `detectInterfaceMapConflicts`:
  - duplicate target → conflict reported;
  - SVI without VLAN → conflict reported;
  - overwrite of a selected sibling → soft warning.
- Integration: `buildBlocks` on the transformed parsed emits the renamed
  interface.

## Out of scope

- IP/subnet overlap detection, conflicting static-route detection, duplicate
  VLAN-name detection (separate future conflict checks).
- Auto-suggesting mappings by subnet/description heuristics (manual only for v1).
