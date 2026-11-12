/* Destination switch models + automatic interface remapping.
 * Pure, browser- and Node-importable.
 *
 * Picking a destination model pre-fills the per-device interface map so legacy
 * port names land on the new hardware's names. It is only a starting point —
 * every row stays editable afterwards.
 */

/** `{m}` in a port pattern is the stack member number. */
export const TARGET_MODELS = [
  {
    id: "c9200cx-12p-2x2g",
    label: "C9200CX-12P-2X2G (12 × 1G, 2 × 10G + 2 × 1G uplinks)",
    downlinks: 12,
    stackable: false,
    uplinks: ["TenGigabitEthernet{m}/1/3", "TenGigabitEthernet{m}/1/4"],
    otherPorts: ["GigabitEthernet{m}/1/1", "GigabitEthernet{m}/1/2"], // copper uplinks, never auto-assigned
  },
  {
    id: "c9200l-24-4x",
    label: "C9200L-24-4X10G (24 × 1G, 4 × 10G uplinks)",
    downlinks: 24,
    stackable: true,
    uplinks: [1, 2, 3, 4].map((n) => `TenGigabitEthernet{m}/1/${n}`),
    otherPorts: [],
  },
  {
    id: "c9200l-48-4x",
    label: "C9200L-48-4X10G (48 × 1G, 4 × 10G uplinks)",
    downlinks: 48,
    stackable: true,
    uplinks: [1, 2, 3, 4].map((n) => `TenGigabitEthernet{m}/1/${n}`),
    otherPorts: [],
  },
];

export function targetModel(id) {
  return TARGET_MODELS.find((m) => m.id === id) || null;
}

/** Every port name on one member of a model (for the target dropdown). */
export function targetPorts(model, member = 1) {
  if (!model) return [];
  const at = (p) => p.replace("{m}", member);
  const down = Array.from({ length: model.downlinks }, (_, i) => `GigabitEthernet${member}/0/${i + 1}`);
  return [...down, ...model.otherPorts.map(at), ...model.uplinks.map(at)];
}

const SPEED_RANK = { FastEthernet: 0, GigabitEthernet: 1, TenGigabitEthernet: 2 };
const PHYS_RE = /^(FastEthernet|GigabitEthernet|TenGigabitEthernet)(\d+)\/(?:(\d+)\/)?(\d+)$/;

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
 * Work out the remap for one device onto a destination model.
 * Returns Map(srcNormName -> { target, transform: "routed", vlan: "" }).
 *
 * Per stack member:
 *  - Uplinks are the source's uplink-module ports (X/1/N), plus — where the
 *    front panel mixes speeds (e.g. Fa0/1-24 + Gi0/1-2) — the faster ports.
 *    If the source has neither, its LAST ports are taken as the uplinks (as
 *    many as the model has 10G uplinks). They map, in order, onto the model's
 *    10G uplinks.
 *  - Every other port keeps its number: X0/N -> GigabitEthernet<m>/0/N.
 *  - Ports that don't fit (number beyond the model's port count, more uplinks
 *    than the model has, extra stack members on a non-stackable model) are left
 *    unmapped for the user to place by hand.
 */
export function autoMapInterfaces(parsed, model) {
  const map = new Map();
  if (!model) return map;

  const byMember = new Map();
  for (const f of parsed.interfaces || []) {
    const p = physicalPort(f.normName);
    if (!p) continue;
    if (!byMember.has(p.member)) byMember.set(p.member, []);
    byMember.get(p.member).push(p);
  }

  for (const [member, ports] of byMember) {
    if (member > 1 && !model.stackable) continue;

    const front = ports.filter((p) => p.module === 0);
    const topRank = Math.max(...front.map((p) => p.rank), 0);
    const mixed = front.some((p) => p.rank !== topRank);

    let access = front.filter((p) => !mixed || p.rank !== topRank).sort((a, b) => a.port - b.port);
    let uplinks = [
      ...(mixed ? front.filter((p) => p.rank === topRank).sort((a, b) => a.port - b.port) : []),
      ...ports.filter((p) => p.module !== 0).sort((a, b) => a.module - b.module || a.rank - b.rank || a.port - b.port),
    ];
    if (!uplinks.length && access.length > model.uplinks.length) {
      uplinks = access.slice(-model.uplinks.length);
      access = access.slice(0, -model.uplinks.length);
    }

    const assign = (src, target) => {
      if (target !== src.normName) map.set(src.normName, { target, transform: "routed", vlan: "" });
    };
    for (const p of access) {
      if (p.port <= model.downlinks) assign(p, `GigabitEthernet${member}/0/${p.port}`);
    }
    uplinks.slice(0, model.uplinks.length).forEach((p, i) => assign(p, model.uplinks[i].replace("{m}", member)));
  }
  return map;
}
