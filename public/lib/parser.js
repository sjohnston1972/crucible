/* Cisco IOS configuration parser (pure, browser- and Node-importable).
 *
 * Indentation-aware, line-by-line. A `!` or any non-indented command ends an
 * indented block. Designed to fail soft: unknown lines are ignored, requested
 * items that are absent are simply not present in the result (callers report
 * "not found" per site rather than throwing).
 *
 * Scope: classic Cisco IOS only (per project decisions §12.5).
 */

// ----------------------------------------------------------- interface naming

const CANON_INTERFACES = [
  "FortyGigabitEthernet",
  "TenGigabitEthernet",
  "TwentyFiveGigE",
  "HundredGigE",
  "GigabitEthernet",
  "FastEthernet",
  "Ethernet",
  "Port-channel",
  "Vlan",
  "Loopback",
  "Tunnel",
  "Serial",
  "Management",
  "Multilink",
];

const INTERFACE_ABBR = {
  gi: "GigabitEthernet",
  gig: "GigabitEthernet",
  te: "TenGigabitEthernet",
  ten: "TenGigabitEthernet",
  fo: "FortyGigabitEthernet",
  fa: "FastEthernet",
  fas: "FastEthernet",
  et: "Ethernet",
  eth: "Ethernet",
  po: "Port-channel",
  vl: "Vlan",
  lo: "Loopback",
  tu: "Tunnel",
  se: "Serial",
  twe: "TwentyFiveGigE",
  hu: "HundredGigE",
  mgmt: "Management",
};

/** Normalise short/long interface names so `Gi0/1` === `GigabitEthernet0/1`. */
export function normalizeInterfaceName(name) {
  if (name == null) return "";
  const trimmed = String(name).trim();
  const m = trimmed.match(/^([A-Za-z][A-Za-z-]*?)\s*([\d].*)?$/);
  if (!m) return trimmed;
  const prefix = m[1];
  const tail = (m[2] || "").replace(/\s+/g, "");
  const p = prefix.toLowerCase();

  let canon = CANON_INTERFACES.find((c) => c.toLowerCase() === p);
  if (!canon) canon = INTERFACE_ABBR[p];
  if (!canon) canon = CANON_INTERFACES.find((c) => c.toLowerCase().startsWith(p));
  return (canon || prefix) + tail;
}

// ----------------------------------------------------------- low-level helpers

const isIndented = (line) => /^[ \t]/.test(line);
const isTerminator = (line) => line.trim() === "!" || (line.trim() !== "" && !isIndented(line));

/**
 * Capture an indented block beginning at `startIdx` (the header line). Returns
 * the header plus all following indented child lines, stopping at `!` or the
 * next non-indented command.
 */
export function extractBlock(lines, startIdx) {
  const block = [lines[startIdx]];
  let j = startIdx + 1;
  for (; j < lines.length; j++) {
    const line = lines[j];
    if (line.trim() === "") continue; // tolerate stray blank lines inside a block
    if (isTerminator(line)) break;
    block.push(line);
  }
  return { block, endIdx: j - 1 };
}

const childLines = (block) => block.slice(1).map((l) => l.trim());

// --------------------------------------------------------------------- parse

export function parse(text) {
  const normalized = String(text == null ? "" : text)
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  const lines = normalized.split("\n");

  const result = {
    hostname: null,
    interfaces: [],
    staticRoutes: [],
    ipv6Routes: [],
    defaultGateway: null, // { nextHop, source: 'default-route' | 'default-gateway', raw }
    protocols: [], // { type, id, header, block: [...], lines: [...] }
    vrfs: [], // { name, legacy, block, rd, routeTargets[], interfaces[], routes[] }
    spanningTree: {
      mode: null,
      extendSystemId: false,
      globalOptions: [],
      vlanConfig: [], // { vlans, priority, root, helloTime, forwardTime, maxAge, raw }
      mstConfig: null, // { name, revision, instances:[{id,vlans}], block, priorities:[] }
      raw: [],
    },
    dhcpPools: [], // { name, block, network, defaultRouter, dnsServers, leases, options[] }
    excludedAddresses: [], // raw lines
    helperAddresses: [], // { interface, ip }
    snmp: [], // snmp-server ... lines
    tacacs: [], // tacacs server / aaa group server tacacs+ blocks + tacacs-server host
    logging: [], // logging ... lines
    ntp: [], // ntp ... lines
    dns: [], // ip name-server / ip domain name|domain-name / ip domain-list lines
    isL3: false, // `ip routing` present
    lines: normalized ? lines : [],
    text: normalized,
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.trim();
    if (line === "" || line === "!") continue;

    // hostname (first wins)
    if (result.hostname === null) {
      const h = line.match(/^hostname\s+(\S+)/);
      if (h) {
        result.hostname = h[1];
        continue;
      }
    }

    if (/^ip routing\b/.test(line)) {
      result.isL3 = true;
      continue;
    }

    // interface block
    const iface = line.match(/^interface\s+(\S+)/);
    if (iface && !isIndented(raw)) {
      const { block, endIdx } = extractBlock(lines, i);
      result.interfaces.push(parseInterface(iface[1], block, result));
      i = endIdx;
      continue;
    }

    // routing protocol block
    const proto = line.match(/^router\s+(\S+)\s*(.*)$/);
    if (proto && !isIndented(raw)) {
      const { block, endIdx } = extractBlock(lines, i);
      result.protocols.push({
        type: proto[1].toLowerCase(),
        id: proto[2].trim(),
        header: line,
        block,
        lines: childLines(block),
      });
      i = endIdx;
      continue;
    }

    // VRF (modern + legacy)
    const vrfDef = line.match(/^vrf definition\s+(\S+)/);
    const ipVrf = line.match(/^ip vrf\s+(\S+)/);
    if ((vrfDef || ipVrf) && !isIndented(raw)) {
      const { block, endIdx } = extractBlock(lines, i);
      result.vrfs.push(parseVrf(vrfDef ? vrfDef[1] : ipVrf[1], !!ipVrf, block));
      i = endIdx;
      continue;
    }

    // static / default routes
    if (/^ip route\s+/.test(line)) {
      result.staticRoutes.push(line);
      const def = line.match(/^ip route\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)/);
      if (def && !result.defaultGateway) {
        result.defaultGateway = { nextHop: def[1], source: "default-route", raw: line };
      }
      continue;
    }
    if (/^ipv6 route\s+/.test(line)) {
      result.ipv6Routes.push(line);
      continue;
    }
    const dg = line.match(/^ip default-gateway\s+(\S+)/);
    if (dg) {
      // A real default route wins over default-gateway if both exist.
      if (!result.defaultGateway || result.defaultGateway.source === "default-gateway") {
        result.defaultGateway = { nextHop: dg[1], source: "default-gateway", raw: line };
      }
      continue;
    }

    // spanning tree
    if (/^spanning-tree\b/.test(line)) {
      i = parseSpanningTree(line, lines, i, raw, result.spanningTree);
      continue;
    }

    // DHCP
    const pool = line.match(/^ip dhcp pool\s+(\S+)/);
    if (pool && !isIndented(raw)) {
      const { block, endIdx } = extractBlock(lines, i);
      result.dhcpPools.push(parseDhcpPool(pool[1], block));
      i = endIdx;
      continue;
    }
    if (/^ip dhcp excluded-address\s+/.test(line)) {
      result.excludedAddresses.push(line);
      continue;
    }

    // management services (scan + carry-over)
    if (/^snmp-server\b/.test(line)) {
      result.snmp.push(line);
      continue;
    }
    if (/^logging\b/.test(line)) {
      result.logging.push(line);
      continue;
    }
    if (/^ntp\b/.test(line)) {
      result.ntp.push(line);
      continue;
    }
    if (/^ip name-server\b/.test(line) || /^ip domain[- ](name|list)\b/.test(line)) {
      result.dns.push(line);
      continue;
    }
    if ((/^tacacs server\b/.test(line) || /^aaa group server tacacs\+/.test(line)) && !isIndented(raw)) {
      const { block, endIdx } = extractBlock(lines, i);
      result.tacacs.push(...block);
      i = endIdx;
      continue;
    }
    if (/^tacacs-server\b/.test(line)) {
      result.tacacs.push(line);
      continue;
    }
  }

  // resolve VRF interface bindings and per-VRF routes from already-parsed data
  for (const vrf of result.vrfs) {
    vrf.interfaces = result.interfaces
      .filter((f) => f.vrf === vrf.name)
      .map((f) => f.normName);
    vrf.routes = result.staticRoutes.filter((r) =>
      new RegExp(`^ip route vrf ${escapeRegex(vrf.name)}\\b`).test(r)
    );
  }

  return result;
}

// ------------------------------------------------------------- block parsers

function parseInterface(name, block, result) {
  const children = childLines(block);
  const iface = {
    name,
    normName: normalizeInterfaceName(name),
    block,
    text: block.join("\n"),
    description: null,
    shutdown: false,
    vrf: null,
    ipAddresses: [], // raw "ip address ..." lines (incl. secondary)
    hasIp: false,
    switchportLines: [],
    stpLines: [], // per-port spanning-tree lines (kept with the interface)
    helperAddresses: [],
    channelGroup: null, // port-channel number this interface is bundled into
  };

  for (const c of children) {
    let m;
    if ((m = c.match(/^description\s+(.*)$/))) iface.description = m[1];
    else if (/^shutdown$/.test(c)) iface.shutdown = true;
    else if ((m = c.match(/^(?:ip )?vrf forwarding\s+(\S+)/))) iface.vrf = m[1];
    else if ((m = c.match(/^channel-group\s+(\d+)/))) iface.channelGroup = Number(m[1]);
    else if (/^ip address\s+/.test(c)) {
      iface.ipAddresses.push(c);
      iface.hasIp = true;
    } else if (/^spanning-tree\s+/.test(c)) iface.stpLines.push(c);
    else if (/^switchport\b/.test(c)) iface.switchportLines.push(c);

    if ((m = c.match(/^ip helper-address\s+(\S+)/))) {
      iface.helperAddresses.push(m[1]);
      result.helperAddresses.push({ interface: iface.normName, ip: m[1] });
    }
  }
  return iface;
}

function parseVrf(name, legacy, block) {
  const children = childLines(block);
  const routeTargets = [];
  let rd = null;
  for (const c of children) {
    let m;
    if ((m = c.match(/^rd\s+(\S+)/))) rd = m[1];
    else if ((m = c.match(/^route-target\s+(.*)$/))) routeTargets.push(m[1]);
  }
  return { name, legacy, block, rd, routeTargets, interfaces: [], routes: [] };
}

function parseDhcpPool(name, block) {
  const children = childLines(block);
  const pool = {
    name,
    block,
    network: null,
    defaultRouter: null,
    dnsServers: null,
    domainName: null,
    lease: null,
    options: [],
  };
  for (const c of children) {
    let m;
    if ((m = c.match(/^network\s+(.*)$/))) pool.network = m[1];
    else if ((m = c.match(/^default-router\s+(.*)$/))) pool.defaultRouter = m[1];
    else if ((m = c.match(/^dns-server\s+(.*)$/))) pool.dnsServers = m[1];
    else if ((m = c.match(/^domain-name\s+(.*)$/))) pool.domainName = m[1];
    else if ((m = c.match(/^lease\s+(.*)$/))) pool.lease = m[1];
    else if ((m = c.match(/^option\s+(.*)$/))) pool.options.push(m[1]);
  }
  return pool;
}

/** Returns the index of the last consumed line (for the caller's loop). */
function parseSpanningTree(line, lines, i, raw, stp) {
  // The MST configuration sub-block is the one indented global STP construct.
  if (/^spanning-tree mst configuration$/.test(line)) {
    const { block, endIdx } = extractBlock(lines, i);
    const mst = { name: null, revision: null, instances: [], block, priorities: [] };
    for (const c of childLines(block)) {
      let m;
      if ((m = c.match(/^name\s+(\S+)/))) mst.name = m[1];
      else if ((m = c.match(/^revision\s+(\d+)/))) mst.revision = Number(m[1]);
      else if ((m = c.match(/^instance\s+(\d+)\s+vlan\s+(.*)$/)))
        mst.instances.push({ id: Number(m[1]), vlans: m[2].trim() });
    }
    stp.mstConfig = { ...(stp.mstConfig || {}), ...mst };
    stp.raw.push(...block);
    return endIdx;
  }

  stp.raw.push(raw);

  let m;
  if ((m = line.match(/^spanning-tree mode\s+(\S+)/))) stp.mode = m[1];
  else if (/^spanning-tree extend system-id$/.test(line)) stp.extendSystemId = true;
  else if ((m = line.match(/^spanning-tree vlan\s+(\S+)\s+(.*)$/))) {
    const entry = { vlans: m[1], raw: line, priority: null, root: null };
    const rest = m[2];
    let mm;
    if ((mm = rest.match(/priority\s+(\d+)/))) entry.priority = Number(mm[1]);
    if ((mm = rest.match(/root\s+(primary|secondary)/))) entry.root = mm[1];
    if ((mm = rest.match(/hello-time\s+(\d+)/))) entry.helloTime = Number(mm[1]);
    if ((mm = rest.match(/forward-time\s+(\d+)/))) entry.forwardTime = Number(mm[1]);
    if ((mm = rest.match(/max-age\s+(\d+)/))) entry.maxAge = Number(mm[1]);
    stp.vlanConfig.push(entry);
  } else if ((m = line.match(/^spanning-tree mst\s+(\d+)\s+(priority|root)\s+(.*)$/))) {
    if (!stp.mstConfig) stp.mstConfig = { instances: [], priorities: [] };
    stp.mstConfig.priorities = stp.mstConfig.priorities || [];
    stp.mstConfig.priorities.push({ instance: Number(m[1]), kind: m[2], value: m[3].trim(), raw: line });
  } else {
    stp.globalOptions.push(line);
  }
  return i;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
