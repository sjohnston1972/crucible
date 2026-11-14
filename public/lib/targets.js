/* Destination switch models + automatic interface remapping.
 * Pure, browser- and Node-importable.
 *
 * Picking a destination model pre-fills the per-device interface map so legacy
 * port names land on the new hardware's names. It is only a starting point —
 * every row stays editable afterwards.
 *
 * Model shape:
 *   id, family, label
 *   downlinks   [{ type, from, to }] front-panel ports <type><m>/0/<from..to>
 *               (several ranges where the type changes across the panel)
 *   uplinks     fixed uplink port patterns, in auto-assign order
 *   modules     [{ id, label, uplinks }] pluggable uplink modules (first = default)
 *   otherPorts  ports offered in the picker but never auto-assigned
 *   maxStack    most members in one stack (1 = does not stack)
 *   variants    exact `switch N provision <keyword>` keywords sharing this layout
 *
 * `{m}` in a port pattern is the stack member number.
 */

const dl = (type, from, to) => ({ type, from, to });
const seq = (type, from, to, mod = 1) =>
  Array.from({ length: to - from + 1 }, (_, i) => `${type}{m}/${mod}/${from + i}`);

const GI = "GigabitEthernet";
const TW = "TwoGigabitEthernet";
const FI = "FiveGigabitEthernet";
const TE = "TenGigabitEthernet";
const TWE = "TwentyFiveGigE";
const FO = "FortyGigabitEthernet";
const HU = "HundredGigE";

/* Port layouts collected from Cisco interface/hardware guides, two real 9300
 * running-configs and the community NetBox device-type library. `variants` are
 * the expected lowercase `switch N provision` keywords: suggestions only. */

// Pluggable uplink modules (first listed = default).
const NM_9300 = [
  { id: "c9300-nm-8x", label: "C9300-NM-8X (8 × 10G)", uplinks: seq(TE, 1, 8) },
  { id: "c9300-nm-4g", label: "C9300-NM-4G (4 × 1G)", uplinks: seq(GI, 1, 4) },
  { id: "c9300-nm-4m", label: "C9300-NM-4M (4 × mGig 10G)", uplinks: seq(TE, 1, 4) },
  { id: "c9300-nm-2y", label: "C9300-NM-2Y (2 × 25G)", uplinks: seq(TWE, 1, 2) },
  { id: "c9300-nm-2q", label: "C9300-NM-2Q (2 × 40G)", uplinks: seq(FO, 1, 2) },
];
const NM_9300X = [
  { id: "c9300x-nm-8y", label: "C9300X-NM-8Y (8 × 25G)", uplinks: seq(TWE, 1, 8) },
  { id: "c9300x-nm-8m", label: "C9300X-NM-8M (8 × mGig 10G)", uplinks: seq(TE, 1, 8) },
  { id: "c9300x-nm-2c", label: "C9300X-NM-2C (2 × 100G)", uplinks: seq(HU, 1, 2) },
];
const NM_9300X_4C = { id: "c9300x-nm-4c", label: "C9300X-NM-4C (4 × 100G)", uplinks: seq(HU, 1, 4) };
const NM_9200 = [
  { id: "c9200-nm-4x", label: "C9200-NM-4X (4 × 10G)", uplinks: seq(TE, 1, 4) },
  { id: "c9200-nm-4g", label: "C9200-NM-4G (4 × 1G)", uplinks: seq(GI, 1, 4) },
];
const NM_9500 = [
  { id: "c9500-nm-8x", label: "C9500-NM-8X (8 × 10G)", uplinks: seq(TE, 1, 8) },
  { id: "c9500-nm-2q", label: "C9500-NM-2Q (2 × 40G)", uplinks: seq(FO, 1, 2) },
];

const F_9200CX = "Catalyst 9200CX (compact, no stacking)";
const F_9200L = "Catalyst 9200L (fixed uplinks, stack of up to 8)";
const F_9200 = "Catalyst 9200 (modular uplinks, stack of up to 8)";
const F_9300L = "Catalyst 9300L / 9300LM (fixed uplinks, stack of up to 8)";
const F_9300 = "Catalyst 9300 (modular uplinks, stack of up to 8)";
const F_9300X = "Catalyst 9300X (modular uplinks, stack of up to 8)";
const F_9500 = "Catalyst 9500 (fixed, no stacking)";

export const TARGET_MODELS = [
  // ---- Catalyst 9200CX compact
  {
    id: "c9200cx-8p-2x2g", family: F_9200CX,
    label: "C9200CX-8P-2X2G (8 × 1G, 2 × 10G + 2 × 1G uplinks)",
    downlinks: [dl(GI, 1, 8)], uplinks: seq(TE, 3, 4), otherPorts: seq(GI, 1, 2),
    maxStack: 1, variants: ["c9200cx-8p-2x2g", "c9200cx-8p-2xgh"],
  },
  {
    id: "c9200cx-12p-2x2g", family: F_9200CX,
    label: "C9200CX-12P-2X2G (12 × 1G, 2 × 10G + 2 × 1G uplinks)",
    downlinks: [dl(GI, 1, 12)], uplinks: seq(TE, 3, 4),
    otherPorts: seq(GI, 1, 2), // copper uplinks, never auto-assigned
    maxStack: 1, variants: ["c9200cx-12p-2x2g", "c9200cx-12p-2xgh", "c9200cx-12t-2x2g"],
  },
  {
    id: "c9200cx-8uxg-2x", family: F_9200CX,
    label: "C9200CX-8UXG-2X (4 × 1G + 4 × mGig 10G, 2 × 10G uplinks)",
    downlinks: [dl(GI, 1, 4), dl(TE, 5, 8)], uplinks: seq(TE, 1, 2),
    maxStack: 1, variants: ["c9200cx-8uxg-2x", "c9200cx-8uxg-2xh"],
  },
  {
    id: "c9200cx-8pt-2g", family: F_9200CX,
    label: "C9200CX-8PT-2G (8 × 1G, 2 × 1G uplinks)",
    downlinks: [dl(GI, 1, 8)], uplinks: seq(GI, 1, 2),
    maxStack: 1, variants: ["c9200cx-8pt-2g"],
  },

  // ---- Catalyst 9200L
  {
    id: "c9200l-24-4g", family: F_9200L,
    label: "C9200L-24T/P-4G (24 × 1G, 4 × 1G uplinks)",
    downlinks: [dl(GI, 1, 24)], uplinks: seq(GI, 1, 4),
    maxStack: 8, variants: ["c9200l-24t-4g", "c9200l-24p-4g"],
  },
  {
    id: "c9200l-48-4g", family: F_9200L,
    label: "C9200L-48T/P/PL-4G (48 × 1G, 4 × 1G uplinks)",
    downlinks: [dl(GI, 1, 48)], uplinks: seq(GI, 1, 4),
    maxStack: 8, variants: ["c9200l-48t-4g", "c9200l-48p-4g", "c9200l-48pl-4g"],
  },
  {
    id: "c9200l-24-4x", family: F_9200L,
    label: "C9200L-24T/P-4X (24 × 1G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 24)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9200l-24t-4x", "c9200l-24p-4x"],
  },
  {
    id: "c9200l-48-4x", family: F_9200L,
    label: "C9200L-48T/P/PL-4X (48 × 1G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 48)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9200l-48t-4x", "c9200l-48p-4x", "c9200l-48pl-4x"],
  },
  {
    id: "c9200l-24pxg-4x", family: F_9200L,
    label: "C9200L-24PXG-4X (16 × 1G + 8 × mGig 10G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 16), dl(TE, 17, 24)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9200l-24pxg-4x"],
  },
  {
    id: "c9200l-48pxg-4x", family: F_9200L,
    label: "C9200L-48PXG-4X (36 × 1G + 12 × mGig 10G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 36), dl(TE, 37, 48)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9200l-48pxg-4x"],
  },
  {
    id: "c9200l-24pxg-2y", family: F_9200L,
    label: "C9200L-24PXG-2Y (16 × 1G + 8 × mGig 10G, 2 × 25G uplinks)",
    downlinks: [dl(GI, 1, 16), dl(TE, 17, 24)], uplinks: seq(TWE, 1, 2),
    maxStack: 8, variants: ["c9200l-24pxg-2y"],
  },
  {
    id: "c9200l-48pxg-2y", family: F_9200L,
    label: "C9200L-48PXG-2Y (40 × 1G + 8 × mGig 10G, 2 × 25G uplinks)",
    downlinks: [dl(GI, 1, 40), dl(TE, 41, 48)], uplinks: seq(TWE, 1, 2),
    maxStack: 8, variants: ["c9200l-48pxg-2y"],
  },

  // ---- Catalyst 9200 (modular uplinks)
  {
    id: "c9200-24", family: F_9200,
    label: "C9200-24T/P/PB (24 × 1G, uplink module)",
    downlinks: [dl(GI, 1, 24)], modules: NM_9200,
    maxStack: 8, variants: ["c9200-24t", "c9200-24p", "c9200-24pb"],
  },
  {
    id: "c9200-48", family: F_9200,
    label: "C9200-48T/P/PB/PL (48 × 1G, uplink module)",
    downlinks: [dl(GI, 1, 48)], modules: NM_9200,
    maxStack: 8, variants: ["c9200-48t", "c9200-48p", "c9200-48pb", "c9200-48pl"],
  },

  // ---- Catalyst 9300L / 9300LM
  {
    id: "c9300l-24-4g", family: F_9300L,
    label: "C9300L-24T/P-4G (24 × 1G, 4 × 1G uplinks)",
    downlinks: [dl(GI, 1, 24)], uplinks: seq(GI, 1, 4),
    maxStack: 8, variants: ["c9300l-24t-4g", "c9300l-24p-4g"],
  },
  {
    id: "c9300l-48-4g", family: F_9300L,
    label: "C9300L-48T/P-4G (48 × 1G, 4 × 1G uplinks)",
    downlinks: [dl(GI, 1, 48)], uplinks: seq(GI, 1, 4),
    maxStack: 8, variants: ["c9300l-48t-4g", "c9300l-48p-4g"],
  },
  {
    id: "c9300l-24-4x", family: F_9300L,
    label: "C9300L-24T/P-4X (24 × 1G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 24)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9300l-24t-4x", "c9300l-24p-4x"],
  },
  {
    id: "c9300l-48-4x", family: F_9300L,
    label: "C9300L-48T/P/PF-4X (48 × 1G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 48)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9300l-48t-4x", "c9300l-48p-4x", "c9300l-48pf-4x"],
  },
  {
    id: "c9300l-48uxg-4x", family: F_9300L,
    label: "C9300L-48UXG-4X (36 × 1G + 12 × mGig 10G, 4 × 10G uplinks)",
    downlinks: [dl(GI, 1, 36), dl(TE, 37, 48)], uplinks: seq(TE, 1, 4),
    maxStack: 8, variants: ["c9300l-48uxg-4x"],
  },
  {
    id: "c9300lm-24u-4y", family: F_9300L,
    label: "C9300LM-24U-4Y (24 × 1G, 4 × 25G uplinks)",
    downlinks: [dl(GI, 1, 24)], uplinks: seq(TWE, 1, 4),
    maxStack: 8, variants: ["c9300lm-24u-4y"],
  },

  // ---- Catalyst 9300 (modular uplinks)
  {
    id: "c9300-24", family: F_9300,
    label: "C9300-24T/P/U/H/S (24 × 1G, uplink module)",
    downlinks: [dl(GI, 1, 24)], modules: NM_9300,
    maxStack: 8, variants: ["c9300-24t", "c9300-24p", "c9300-24u", "c9300-24h", "c9300-24s"],
  },
  {
    id: "c9300-48", family: F_9300,
    label: "C9300-48T/P/U/H/S (48 × 1G, uplink module)",
    downlinks: [dl(GI, 1, 48)], modules: NM_9300,
    maxStack: 8, variants: ["c9300-48t", "c9300-48p", "c9300-48u", "c9300-48h", "c9300-48s"],
  },
  {
    id: "c9300-24ux", family: F_9300,
    label: "C9300-24UX/UXB (24 × mGig 10G, uplink module)",
    downlinks: [dl(TE, 1, 24)], modules: NM_9300,
    maxStack: 8, variants: ["c9300-24ux", "c9300-24uxb"],
  },
  {
    id: "c9300-48uxm", family: F_9300,
    label: "C9300-48UXM (36 × 2.5G + 12 × mGig 10G, uplink module)",
    downlinks: [dl(TW, 1, 36), dl(TE, 37, 48)], modules: NM_9300,
    maxStack: 8, variants: ["c9300-48uxm"],
  },
  {
    id: "c9300-48un", family: F_9300,
    label: "C9300-48UN (48 × 5G, uplink module)",
    downlinks: [dl(FI, 1, 48)], modules: NM_9300,
    maxStack: 8, variants: ["c9300-48un"],
  },

  // ---- Catalyst 9300X
  {
    id: "c9300x-12y", family: F_9300X,
    label: "C9300X-12Y (12 × 25G, uplink module)",
    downlinks: [dl(TWE, 1, 12)], modules: NM_9300X,
    maxStack: 8, variants: ["c9300x-12y"],
  },
  {
    id: "c9300x-24y", family: F_9300X,
    label: "C9300X-24Y (24 × 25G, uplink module)",
    downlinks: [dl(TWE, 1, 24)], modules: [...NM_9300X, NM_9300X_4C],
    maxStack: 8, variants: ["c9300x-24y"],
  },
  {
    id: "c9300x-24hx", family: F_9300X,
    label: "C9300X-24HX (24 × mGig 10G, uplink module)",
    downlinks: [dl(TE, 1, 24)], modules: NM_9300X,
    maxStack: 8, variants: ["c9300x-24hx"],
  },
  {
    id: "c9300x-48hx", family: F_9300X,
    label: "C9300X-48HX/TX (48 × mGig 10G, uplink module)",
    downlinks: [dl(TE, 1, 48)], modules: NM_9300X,
    maxStack: 8, variants: ["c9300x-48hx", "c9300x-48tx"],
  },
  {
    id: "c9300x-48hxn", family: F_9300X,
    label: "C9300X-48HXN (40 × 5G + 8 × mGig 10G, uplink module)",
    downlinks: [dl(FI, 1, 40), dl(TE, 41, 48)], modules: NM_9300X,
    maxStack: 8, variants: ["c9300x-48hxn"],
  },

  // ---- Catalyst 9500 (fixed; uplinks continue the front-panel numbering)
  {
    id: "c9500-24y4c", family: F_9500,
    label: "C9500-24Y4C (24 × 25G, 4 × 100G uplinks)",
    downlinks: [dl(TWE, 1, 24)], uplinks: seq(HU, 25, 28, 0),
    maxStack: 1, variants: [],
  },
  {
    id: "c9500-48y4c", family: F_9500,
    label: "C9500-48Y4C (48 × 25G, 4 × 100G uplinks)",
    downlinks: [dl(TWE, 1, 48)], uplinks: seq(HU, 49, 52, 0),
    maxStack: 1, variants: [],
  },
  {
    id: "c9500-16x", family: F_9500,
    label: "C9500-16X (16 × 10G, uplink module)",
    downlinks: [dl(TE, 1, 16)], modules: NM_9500,
    maxStack: 1, variants: [],
  },
  {
    id: "c9500-40x", family: F_9500,
    label: "C9500-40X (40 × 10G, uplink module)",
    downlinks: [dl(TE, 1, 40)], modules: NM_9500,
    maxStack: 1, variants: [],
  },
  {
    id: "c9500-24q", family: F_9500,
    label: "C9500-24Q (24 × 40G)",
    downlinks: [dl(FO, 1, 24)],
    maxStack: 1, variants: [],
  },
  {
    id: "c9500-32c", family: F_9500,
    label: "C9500-32C (32 × 100G)",
    downlinks: [dl(HU, 1, 32)],
    maxStack: 1, variants: [],
  },
];

export function targetModel(id) {
  return TARGET_MODELS.find((m) => m.id === id) || null;
}

// ------------------------------------------------------------ model helpers

/** Number of front-panel (module 0) downlink ports per member. */
export function downlinkCount(model) {
  return Math.max(0, ...(model.downlinks || []).map((r) => r.to));
}

/** Full name of downlink port n on a member, or null if the model has no such port. */
export function downlinkName(model, member, n) {
  const r = (model.downlinks || []).find((x) => n >= x.from && n <= x.to);
  return r ? `${r.type}${member}/0/${n}` : null;
}

/** The uplink module in use: the one asked for, else the model's first (default). */
export function targetModule(model, moduleId) {
  const mods = (model && model.modules) || [];
  return mods.find((x) => x.id === moduleId) || mods[0] || null;
}

/** Uplink port patterns for a model with a given uplink module fitted. */
export function modelUplinks(model, moduleId) {
  const mod = targetModule(model, moduleId);
  return [...(model.uplinks || []), ...(mod ? mod.uplinks : [])];
}

/** How many members to build: asked-for count clamped to what the model can stack. */
export function stackSize(model, members) {
  const max = (model && model.maxStack) || 1;
  const n = Math.floor(Number(members));
  return Math.min(Math.max(Number.isFinite(n) ? n : 1, 1), max);
}

/**
 * Every port name on a model (for the target dropdown), for each stack member.
 * opts: { members: how many stack members (default 1), module: uplink module id }
 */
export function targetPorts(model, opts = {}) {
  if (!model) return [];
  const out = [];
  const count = stackSize(model, opts.members || 1);
  for (let member = 1; member <= count; member++) {
    const at = (p) => p.replace("{m}", member);
    for (const r of model.downlinks || []) {
      for (let n = r.from; n <= r.to; n++) out.push(`${r.type}${member}/0/${n}`);
    }
    out.push(...(model.otherPorts || []).map(at), ...modelUplinks(model, opts.module).map(at));
  }
  return out;
}

// ------------------------------------------------------------- source ports

const SPEED_RANK = {
  FastEthernet: 0,
  GigabitEthernet: 1,
  TwoGigabitEthernet: 2,
  FiveGigabitEthernet: 3,
  TenGigabitEthernet: 4,
  TwentyFiveGigE: 5,
  FortyGigabitEthernet: 6,
  HundredGigE: 7,
};
const PHYS_RE = new RegExp(`^(${Object.keys(SPEED_RANK).join("|")})(\\d+)\\/(?:(\\d+)\\/)?(\\d+)$`);
const MAX_MIXED_UPLINKS = 8; // more faster ports than this = a multigigabit panel, not uplinks

/** Split a normalised physical port name; null for anything that isn't a front-panel port. */
function physicalPort(normName) {
  const m = PHYS_RE.exec(normName);
  if (!m) return null;
  const threePart = m[3] !== undefined;
  const port = Number(m[4]);
  if (port < 1) return null; // Gi0/0 = management
  return {
    normName,
    rank: SPEED_RANK[m[1]],
    // Fixed legacy switches name ports X0/N; treat that as stack member 1.
    member: threePart ? Number(m[2]) : Math.max(Number(m[2]), 1),
    module: threePart ? Number(m[3]) : 0,
    port,
  };
}

/**
 * Stack members a source config describes: from its `switch N provision` lines
 * plus the member numbers its port names use (Gi2/0/1, Gi2/1 → member 2;
 * Gi0/1 → member 1). Returns { members: [n…] sorted, provisioned: Map(n → model) }.
 */
export function sourceStack(parsed) {
  const provisioned = new Map();
  for (const s of (parsed && parsed.stackMembers) || []) provisioned.set(s.member, s.model);
  const members = new Set(provisioned.keys());
  for (const f of (parsed && parsed.interfaces) || []) {
    const p = physicalPort(f.normName);
    if (p) members.add(p.member);
  }
  return { members: [...members].sort((a, b) => a - b), provisioned };
}

// ------------------------------------------------------------------ auto map

/**
 * Work out the remap for one device onto a destination model.
 * opts: { members: stack members being built (default: as many as the model
 *         can stack), module: uplink module id }
 * Returns Map(srcNormName -> { target, transform: "routed", vlan: "" }).
 *
 * Per stack member:
 *  - Uplinks are the source's uplink-module ports (X/1/N), plus — where the
 *    front panel mixes speeds (e.g. Fa0/1-24 + Gi0/1-2) — the few faster ports.
 *    If the source has neither, its LAST ports are taken as the uplinks (as
 *    many as the model has uplinks). A source uplink already carrying one of the
 *    model's uplink names keeps it; the rest map, configured ports first, onto
 *    the model's remaining uplinks in order.
 *  - Every other port keeps its number and takes the model's port type at that
 *    position: X0/N -> <type><m>/0/N (Gi, Two, Five, Ten, TwentyFive…).
 *  - Ports that don't fit (number beyond the model's port count, more uplinks
 *    than the model has, members beyond the stack being built) are left
 *    unmapped for the user to place by hand.
 */
export function autoMapInterfaces(parsed, model, opts = {}) {
  const map = new Map();
  if (!model) return map;
  const members = stackSize(model, opts.members == null ? model.maxStack : opts.members);
  const uplinkPatterns = modelUplinks(model, opts.module);
  const configured = new Set(
    (parsed.interfaces || []).filter((f) => (f.block || []).length > 1).map((f) => f.normName)
  );

  const byMember = new Map();
  for (const f of parsed.interfaces || []) {
    const p = physicalPort(f.normName);
    if (!p) continue;
    if (!byMember.has(p.member)) byMember.set(p.member, []);
    byMember.get(p.member).push(p);
  }

  for (const [member, ports] of byMember) {
    if (member > members) continue;

    const front = ports.filter((p) => p.module === 0);
    const topRank = Math.max(...front.map((p) => p.rank), 0);
    const faster = front.filter((p) => p.rank === topRank);
    const mixed = faster.length !== front.length && faster.length <= MAX_MIXED_UPLINKS;

    let access = front.filter((p) => !mixed || p.rank !== topRank).sort((a, b) => a.port - b.port);
    let uplinks = [
      ...(mixed ? faster.sort((a, b) => a.port - b.port) : []),
      ...ports.filter((p) => p.module !== 0).sort((a, b) => a.module - b.module || a.rank - b.rank || a.port - b.port),
    ];
    if (!uplinks.length && uplinkPatterns.length && access.length > uplinkPatterns.length) {
      uplinks = access.slice(-uplinkPatterns.length);
      access = access.slice(0, -uplinkPatterns.length);
    }

    const used = new Set();
    const assign = (src, target) => {
      if (used.has(target)) return; // two source ports can never share a target
      used.add(target);
      if (target !== src.normName) map.set(src.normName, { target, transform: "routed", vlan: "" });
    };
    for (const p of access) {
      const target = downlinkName(model, member, p.port);
      if (target) assign(p, target);
    }

    const slots = uplinkPatterns.map((u) => u.replace("{m}", member));
    const keep = uplinks.filter((p) => slots.includes(p.normName));
    keep.forEach((p) => assign(p, p.normName));
    const free = slots.filter((s) => !used.has(s));
    uplinks
      .filter((p) => !keep.includes(p))
      .sort((a, b) => Number(configured.has(b.normName)) - Number(configured.has(a.normName)))
      .slice(0, free.length)
      .forEach((p, i) => assign(p, free[i]));
  }
  return map;
}

// --------------------------------------------------------------------- stack

/**
 * `switch N provision <keyword>` lines for the stack being built. `keyword` is
 * the exact model keyword (one of model.variants, or typed by hand); without
 * one nothing is written.
 */
export function stackProvisionLines(model, members, keyword) {
  const kw = String(keyword || "").trim();
  if (!model || !kw) return [];
  return Array.from({ length: stackSize(model, members) }, (_, i) => `switch ${i + 1} provision ${kw}`);
}

/** Drop any `switch N provision …` lines from a config (they are being re-written). */
export function stripProvisionLines(content) {
  return String(content)
    .split("\n")
    .filter((l) => !/^switch\s+\d+\s+provision\s+\S/.test(l))
    .join("\n");
}

/**
 * Plain-language warnings about fitting a source stack onto the chosen model.
 * opts: { members, keyword, label }
 */
export function stackWarnings(parsed, model, opts = {}) {
  const out = [];
  if (!model) return out;
  const label = opts.label || "device";
  const src = sourceStack(parsed).members;
  const building = stackSize(model, opts.members == null ? model.maxStack : opts.members);
  const dropped = src.filter((m) => m > building);

  if (dropped.length) {
    const why =
      model.maxStack === 1
        ? `${model.label.split(" (")[0]} does not stack`
        : Number(opts.members) > model.maxStack
        ? `${model.label.split(" (")[0]} stacks at most ${model.maxStack}`
        : `the new stack is set to ${building} member${building === 1 ? "" : "s"}`;
    out.push(
      `${label}: source uses stack member${dropped.length === 1 ? "" : "s"} ${dropped.join(", ")} but ${why} — ` +
        `those ports are not auto-mapped; place them by hand.`
    );
  }
  if (src.length > 1 && building > 1 && !String(opts.keyword || "").trim()) {
    out.push(`${label}: no exact model variant chosen, so no "switch N provision" lines were written for the new stack.`);
  }
  return out;
}
