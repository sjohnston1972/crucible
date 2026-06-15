/* Crucible — client orchestration.
 *
 * Discovery → collection form → live tag map → analyze (parse + audit) →
 * STP root election + hardening review → save (build template + write-back/zip).
 *
 * Local files never leave the browser. Only a redacted digest is sent to
 * /api/harden for advisory AI review.
 */

import { parse, normalizeInterfaceName } from "./lib/parser.js";
import { audit, remediationLines } from "./lib/hardening.js";
import {
  buildTagMap,
  buildBlocks,
  renderTagBased,
  renderDirect,
  computeOutput,
  applyHostname,
  buildSecureAccess,
  buildVtp,
  buildClock,
  buildStpHardening,
  buildErrdisable,
  buildBanner,
  applyInterfaceMap,
  detectInterfaceMapConflicts,
} from "./lib/template.js";
import { redactForAI } from "./lib/redact.js";
import { buildZip } from "./lib/zip.js";

const CONFIG_EXT = /\.(txt|cfg)$/i;
const isConfigFile = (name) => CONFIG_EXT.test(name);

// Distinct accent colours assigned per port-channel number (cycled if exceeded).
const PO_PALETTE = ["#2f8d99", "#7c4dff", "#2f9e57", "#cf4f86", "#3f7fd6", "#c98a3a", "#1f9aa8", "#8e9b34"];

/** Port-channel number an interface relates to: a member's channel-group, or the aggregate's own number. */
function interfacePo(f) {
  if (f.channelGroup != null) return f.channelGroup;
  const m = f.normName.match(/^Port-channel(\d+)/i);
  return m ? Number(m[1]) : null;
}

const state = {
  mode: null, // 'primary' | 'fallback'
  rootHandle: null,
  sites: [], // { path, name, dirHandle?, files: [...], parsedFiles: [{ name, entry, parsed }] }
  mergeSel: new Map(), // sitePath -> Set(fileName) committed to merge into one template
  mergeName: new Map(), // sitePath -> custom hostname for the merged device
  units: [], // built output units
  deviceCfg: new Map(), // unitId -> per-device collection state (see defaultDeviceCfg)
  rootBySite: new Map(), // sitePath -> unitId elected as that site's spanning-tree root
  poColor: new Map(), // port-channel number -> colour (computed per scan)
  stpVlans: null,
};

const $ = (id) => document.getElementById(id);

// ----------------------------------------------------------------- mode detect

function detectMode() {
  state.mode = "showDirectoryPicker" in window ? "primary" : "fallback";
  const badge = $("mode-badge");
  if (state.mode === "primary") {
    badge.dataset.mode = "primary";
    badge.textContent = "Read/Write mode";
  } else {
    badge.dataset.mode = "fallback";
    badge.textContent = "Read-only (fallback)";
    $("fallback-note").classList.remove("hidden");
  }
}

// ----------------------------------------------------------------- discovery

async function onBrowse() {
  if (state.mode === "primary") await browsePrimary();
  else $("fallback-input").click();
}

async function browsePrimary() {
  let handle;
  try {
    handle = await window.showDirectoryPicker({ mode: "readwrite" });
  } catch (err) {
    if (err && err.name === "AbortError") return;
    return reportError(err);
  }
  state.rootHandle = handle;
  $("folder-name").textContent = handle.name;
  $("sites-summary").textContent = "Scanning folders…";
  try {
    state.sites = await discoverSitesFSA(handle, handle.name);
    renderSites();
  } catch (err) {
    reportError(err);
  }
}

function onFallbackPicked(event) {
  const files = Array.from(event.target.files || []);
  if (!files.length) return;
  $("folder-name").textContent = files[0].webkitRelativePath.split("/")[0] || "(folder)";
  state.sites = discoverSitesFromFileList(files);
  renderSites();
}

async function discoverSitesFSA(dirHandle, path) {
  const sites = [];
  const files = [];
  const subdirs = [];
  for await (const [name, child] of dirHandle.entries()) {
    if (child.kind === "file") {
      if (isConfigFile(name)) files.push({ name, handle: child });
    } else if (child.kind === "directory") subdirs.push([name, child]);
  }
  if (files.length) {
    files.sort((a, b) => a.name.localeCompare(b.name));
    sites.push({ path, name: dirHandle.name, dirHandle, files });
  }
  subdirs.sort((a, b) => a[0].localeCompare(b[0]));
  for (const [name, child] of subdirs) {
    sites.push(...(await discoverSitesFSA(child, `${path}/${name}`)));
  }
  return sites;
}

function discoverSitesFromFileList(files) {
  const byDir = new Map();
  for (const file of files) {
    if (!isConfigFile(file.name)) continue;
    const parts = file.webkitRelativePath.split("/");
    parts.pop();
    const dirPath = parts.join("/") || "(root)";
    if (!byDir.has(dirPath)) byDir.set(dirPath, []);
    byDir.get(dirPath).push({ name: file.name, file });
  }
  const sites = [];
  for (const [path, fileList] of byDir) {
    fileList.sort((a, b) => a.name.localeCompare(b.name));
    sites.push({ path, name: path.split("/").pop(), files: fileList });
  }
  sites.sort((a, b) => a.path.localeCompare(b.path));
  return sites;
}

function renderSites() {
  if (!state.sites.length) {
    $("sites-summary").textContent = "No sites found — no folder directly contains a .txt/.cfg file.";
    return;
  }
  const fileTotal = state.sites.reduce((n, s) => n + s.files.length, 0);
  $("sites-summary").textContent =
    `${state.sites.length} site${state.sites.length === 1 ? "" : "s"} · ${fileTotal} config file${fileTotal === 1 ? "" : "s"} — analysed below.`;
  // Run analysis automatically as soon as a folder is scanned (results render here in Step 2).
  onAnalyze().catch(reportError);
}

// ----------------------------------------------------------------- form: config

function addInterfaceRow(name = "", mode = "full") {
  const rows = $("iface-rows");
  const row = document.createElement("div");
  row.className = "iface-row";
  row.innerHTML =
    `<input class="if-name" type="text" placeholder="Gi1/0/1 or Vlan10" value="${escapeHtml(name)}" />` +
    `<select class="if-mode"><option value="full"${mode === "full" ? " selected" : ""}>All data</option>` +
    `<option value="ip"${mode === "ip" ? " selected" : ""}>IP only</option></select>` +
    `<button class="btn btn-small btn-ghost if-remove" type="button" title="Remove">✕</button>`;
  row.querySelector(".if-remove").addEventListener("click", () => {
    row.remove();
    refreshTagMap();
  });
  row.querySelectorAll("input,select").forEach((el) => el.addEventListener("input", refreshTagMap));
  rows.appendChild(row);
  refreshTagMap();
}

function dedupInterfaces(list) {
  const out = [];
  const seen = new Set();
  for (const it of list) {
    const key = normalizeInterfaceName(it.name);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

/** Global-only settings — collection is now per-device (see deviceCfg / unitConfig). */
function readGlobalConfig() {
  return {
    secureAccess: {
      enabled: $("sec-enable").checked,
      username: $("sec-user").value.trim(),
      password: $("sec-pass").value.trim(),
      enableSecret: $("sec-enable-secret").value.trim(),
      configKey: $("sec-configkey").value.trim(),
    },
    vtp: {
      enabled: $("vtp-enable").checked,
      domain: $("vtp-domain").value.trim(),
      password: $("vtp-password").value.trim(),
      mode: $("vtp-mode").value,
    },
    clock: {
      enabled: $("clock-enable").checked,
      timezone: $("clock-tz").value.trim(),
      offset: $("clock-offset").value.trim(),
      summerTime: $("clock-summer").value.trim(),
    },
    stpHardening: { enabled: $("stph-enable").checked },
    errdisable: { enabled: $("errd-enable").checked, interval: $("errd-interval").value.trim() },
    banner: { enabled: $("banner-enable").checked, text: $("banner-text").value },
    insertion: document.querySelector('input[name="insertion"]:checked').value,
    naming: {
      rename: $("rename").checked,
      method: $("rename-method").value,
      find: $("rename-find").value,
      replace: $("rename-replace").value,
    },
  };
}

/** Per-device collection state, pre-seeded with whatever the device actually has. */
function defaultDeviceCfg(p) {
  return {
    interfacesAll: { enabled: false, mode: "full" },
    ifaceSel: new Map(), // normName -> { checked, mode }
    ifaceMap: new Map(), // normName -> { target, transform: "routed"|"svi", vlan }
    routing: {
      defaultGateway: !!p.defaultGateway,
      allStatic: p.staticRoutes.length > 0,
      protocols: p.protocols.length > 0,
    },
    vrf: p.vrfs.length > 0,
    stp: !!p.spanningTree.mode,
    dhcp: p.dhcpPools.length > 0,
    snmp: p.snmp.length > 0,
    tacacs: p.tacacs.length > 0,
    logging: p.logging.length > 0,
    ntp: p.ntp.length > 0,
    dns: p.dns.length > 0,
  };
}
function deviceCfg(unit) {
  if (!state.deviceCfg.has(unit.id)) state.deviceCfg.set(unit.id, defaultDeviceCfg(unit.parsed));
  return state.deviceCfg.get(unit.id);
}

/** Translate per-interface selections through the device's ifaceMap so the slot
 * lookup matches the transformed parsed; SVI selections fan out to the access
 * port + the synthesized Vlan SVI. */
function mappedSelections(selected, ifaceMap) {
  if (!ifaceMap || ifaceMap.size === 0) return selected;
  const out = [];
  const seen = new Set();
  const push = (name, mode) => {
    const k = name + "::" + mode;
    if (!seen.has(k)) { seen.add(k); out.push({ name, mode }); }
  };
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

/** Build a buildBlocks/buildTagMap config for one device from its per-device state + globals. */
function unitConfig(unit, global) {
  const d = deviceCfg(unit);
  const interfaces = d.interfacesAll.enabled
    ? []
    : mappedSelections(
        [...d.ifaceSel.entries()].filter(([, v]) => v.checked).map(([name, v]) => ({ name, mode: v.mode })),
        d.ifaceMap
      );
  return {
    interfacesAll: d.interfacesAll,
    interfaces,
    routing: d.routing,
    vrf: { enabled: d.vrf },
    stp: { enabled: d.stp },
    dhcp: { enabled: d.dhcp },
    snmp: { enabled: d.snmp },
    tacacs: { enabled: d.tacacs },
    logging: { enabled: d.logging },
    ntp: { enabled: d.ntp },
    dns: { enabled: d.dns },
    insertion: global.insertion,
    naming: global.naming,
  };
}

function refreshTagMap() {
  const el = $("tagmap");
  el.innerHTML = "";
  const rep = state.units[0];
  if (!rep) {
    el.innerHTML = `<p class="muted small">Scan a folder to compute the tag map.</p>`;
    return;
  }
  if (state.units.length > 1) {
    const note = document.createElement("p");
    note.className = "muted small";
    note.textContent = `Tags shown for ${rep.parsed.hostname || rep.sourceNames[0]}; each device's auto-template matches its own selection.`;
    el.appendChild(note);
  }
  for (const slot of buildTagMap(unitConfig(rep, readGlobalConfig()))) {
    const div = document.createElement("div");
    div.className = "tag-entry";
    div.innerHTML = `<span class="tag-marker">{${slot.tag}}</span><span class="tag-label">${escapeHtml(slot.label)}</span>`;
    el.appendChild(div);
  }
}

/** Distinct colour per port-channel number across the whole scan. */
function computePoColors() {
  const poNums = [
    ...new Set(
      state.units.flatMap((u) => (u.parsed.interfaces || []).map(interfacePo).filter((n) => n != null))
    ),
  ].sort((a, b) => a - b);
  state.poColor = new Map(poNums.map((n, i) => [n, PO_PALETTE[i % PO_PALETTE.length]]));
}

/** Build one interface tile bound to a device's per-device selection map. */
function buildIfaceTile(unit, f) {
  const d = deviceCfg(unit);
  const sel = d.ifaceSel.get(f.normName) || { checked: false, mode: "full" };
  const key = `${unit.id}::${f.normName}`;
  state.ifaceConfigs.set(key, {
    text: f.text || (f.block || []).join("\n"),
    host: unit.parsed.hostname || unit.sourceNames[0],
    shutdown: !!f.shutdown,
  });
  const po = interfacePo(f);
  const isAggregate = f.channelGroup == null && po != null;
  const tile = document.createElement("div");
  tile.className = "disc-if" + (po != null ? " bundled" : "") + (f.shutdown ? " shutdown" : "");
  if (po != null) tile.style.setProperty("--po-color", state.poColor.get(po));
  tile.dataset.unit = unit.id;
  tile.dataset.name = f.normName;
  const badges =
    (f.shutdown ? '<span class="disc-if-shut">SHUT</span>' : "") +
    (po != null
      ? isAggregate
        ? `<span class="disc-if-po" title="Port-channel ${po} aggregate interface">PO${po} aggregate</span>`
        : `<span class="disc-if-po" title="Bundled into Port-channel${po}">bundled PO${po}</span>`
      : "");
  tile.innerHTML =
    `<label class="disc-if-main"><input type="checkbox" class="disc-if-cb"${sel.checked ? " checked" : ""} />` +
    `<span class="disc-if-name">${escapeHtml(f.normName)}</span></label>` +
    `<div class="disc-if-row2"><span class="disc-if-badges">${badges}</span>` +
    `<select class="disc-if-mode"><option value="full"${sel.mode !== "ip" ? " selected" : ""}>All data</option>` +
    `<option value="ip"${sel.mode === "ip" ? " selected" : ""}>IP only</option></select></div>`;
  const cb = tile.querySelector(".disc-if-cb");
  const modeSel = tile.querySelector(".disc-if-mode");
  const update = () => {
    d.ifaceSel.set(f.normName, { checked: cb.checked, mode: modeSel.value });
    refreshTagMap();
  };
  cb.addEventListener("change", update);
  modeSel.addEventListener("change", update);
  tile.addEventListener("mouseenter", () => showIfaceTip(key, tile));
  tile.addEventListener("mouseleave", hideIfaceTip);
  return tile;
}

function showIfaceTip(key, anchor) {
  const info = state.ifaceConfigs && state.ifaceConfigs.get(key);
  const tip = $("iface-tip");
  if (!info) return;
  tip.textContent = `! from ${info.host}\n${info.text || "(no config captured)"}`;
  tip.classList.remove("hidden");
  const r = anchor.getBoundingClientRect();
  const docW = document.documentElement.clientWidth;
  let left = window.scrollX + r.left;
  const maxLeft = window.scrollX + docW - tip.offsetWidth - 12;
  if (left > maxLeft) left = Math.max(window.scrollX + 8, maxLeft);
  tip.style.top = `${window.scrollY + r.bottom + 6}px`;
  tip.style.left = `${left}px`;
}

function hideIfaceTip() {
  $("iface-tip").classList.add("hidden");
}

// ----------------------------------------------------------------- template file

async function onChooseTemplateFSA() {
  // Prefer the file picker via <input> for broad support; FSA picker optional.
  $("template-input").click();
}

async function onTemplatePicked(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const text = await file.text();
  state.template = { name: file.name, text };
  $("template-name").textContent = file.name;
  $("btn-clear-template").classList.remove("hidden");
}

function onClearTemplate() {
  state.template = null;
  $("template-input").value = "";
  $("template-name").textContent = "Using auto-generated template";
  $("btn-clear-template").classList.add("hidden");
}

// ----------------------------------------------------------------- read helpers

async function readEntryText(entry) {
  if (entry.text != null) return entry.text; // sample / preloaded data
  if (entry.handle) return (await entry.handle.getFile()).text();
  if (entry.file) return entry.file.text();
  return "";
}

// ----------------------------------------------------------------- sample / clear

async function loadSampleData() {
  $("sites-summary").textContent = "Loading sample data…";
  try {
    const res = await fetch("/sample-data/manifest.json");
    if (!res.ok) throw new Error(`could not load sample manifest (${res.status})`);
    const manifest = await res.json();
    const sites = [];
    for (const site of manifest) {
      const files = [];
      for (const f of site.files) {
        const r = await fetch(`/sample-data/${encodeURI(f.url)}`);
        if (!r.ok) throw new Error(`could not load ${f.name} (${r.status})`);
        files.push({ name: f.name, text: await r.text() });
      }
      sites.push({ path: site.path, name: site.path, files });
    }
    state.rootHandle = null;
    state.mergeSel = new Map();
    state.sites = sites;
    $("folder-name").textContent = `Sample data · ${sites.length} sites`;
    renderSites(); // auto-analyzes
  } catch (err) {
    reportError(err);
  }
}

function clearAll() {
  state.rootHandle = null;
  state.sites = [];
  state.mergeSel = new Map();
  state.mergeName = new Map();
  state.units = [];
  state.deviceCfg = new Map();
  state.rootBySite = new Map();
  state.template = null;
  state.ifaceConfigs = new Map();
  state.stpVlans = null;
  $("folder-name").textContent = "";
  $("sites-summary").textContent = "No folder selected yet.";
  $("results").innerHTML = "";
  $("template-name").textContent = "Using auto-generated template";
  $("template-input").value = "";
  $("btn-clear-template").classList.add("hidden");
  $("warnings").innerHTML = "";
  $("run-status").textContent = "";
  $("btn-save").disabled = true;
  refreshTagMap();
}

// ----------------------------------------------------------------- theme

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("theme-toggle").textContent = theme === "dark" ? "☀" : "☾";
  try {
    localStorage.setItem("crucible-theme", theme);
  } catch {
    /* ignore */
  }
}
function toggleTheme() {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
}

/**
 * Flag conflicting spanning-tree intent across sources being collapsed into one
 * L3 switch (§4.6, §12.6). Root election is resolved by user choice; here we
 * only surface MST instance-to-VLAN overlaps and competing root-primary claims
 * for a manual decision — we never silently merge them.
 */
function detectStpConflicts(parsedList, site) {
  const warnings = [];
  const stps = parsedList.map((p) => p.spanningTree).filter((s) => s && (s.mode || s.vlanConfig.length || s.mstConfig));
  if (stps.length < 2) return warnings;

  // Competing root-primary claims
  const rootClaims = stps.filter((s) => (s.vlanConfig || []).some((v) => v.root === "primary"));
  if (rootClaims.length > 1) {
    warnings.push(`${site.path}: ${rootClaims.length} sources both claim spanning-tree root primary — elect one root for the scan.`);
  }

  // Overlapping MST instance → different VLAN mapping
  const instMap = new Map(); // instance id -> vlans string
  for (const s of stps) {
    for (const inst of s.mstConfig?.instances || []) {
      if (instMap.has(inst.id) && instMap.get(inst.id) !== inst.vlans) {
        warnings.push(`${site.path}: MST instance ${inst.id} maps to different VLANs across sources ("${instMap.get(inst.id)}" vs "${inst.vlans}") — resolve manually.`);
      } else {
        instMap.set(inst.id, inst.vlans);
      }
    }
  }
  return warnings;
}

/** Merge several parsed configs into one (for the merge-into-L3 case). */
function mergeParsed(list) {
  if (list.length === 1) return list[0];
  const merged = parse(""); // empty shell
  merged.hostname = list.find((p) => p.hostname)?.hostname || null;
  merged.text = list.map((p) => p.text).join("\n!\n");
  merged.lines = list.flatMap((p) => p.lines);
  for (const p of list) {
    merged.interfaces.push(...p.interfaces);
    merged.staticRoutes.push(...p.staticRoutes);
    merged.ipv6Routes.push(...p.ipv6Routes);
    merged.protocols.push(...p.protocols);
    merged.vrfs.push(...p.vrfs);
    merged.dhcpPools.push(...p.dhcpPools);
    merged.excludedAddresses.push(...p.excludedAddresses);
    merged.helperAddresses.push(...p.helperAddresses);
    if (!merged.defaultGateway && p.defaultGateway) merged.defaultGateway = p.defaultGateway;
    if (p.isL3) merged.isL3 = true;
  }
  // spanning-tree: prefer the first source that has a mode
  const stpSource = list.find((p) => p.spanningTree.mode) || list[0];
  merged.spanningTree = stpSource.spanningTree;
  return merged;
}

// ----------------------------------------------------------------- analyze

function isSwitchParsed(p) {
  return (
    (p.interfaces || []).some((f) => f.switchportLines.length) ||
    !!p.spanningTree.mode ||
    (p.interfaces || []).some((f) => f.stpLines.length)
  );
}
const deviceType = (p) => (isSwitchParsed(p) ? "switch" : "router");

/** A site holding at least one switch and at least one router is a merge candidate. */
function isMergeCandidate(parsedFiles) {
  if (!parsedFiles || parsedFiles.length < 2) return false;
  const types = new Set(parsedFiles.map((pf) => deviceType(pf.parsed)));
  return types.has("switch") && types.has("router");
}

/** Parse every file, cache results, seed default merge selections, render Step 3, build units. */
async function onAnalyze() {
  if (!state.sites.length) return;
  $("run-status").textContent = "Parsing…";
  $("warnings").innerHTML = "";
  try {
    for (const site of state.sites) {
      site.parsedFiles = [];
      for (const entry of site.files) {
        const text = await readEntryText(entry);
        site.parsedFiles.push({ name: entry.name, entry, parsed: parse(text) });
      }
      // Candidates start UN-merged — the user explicitly merges via the merge tile's button.
      if (!state.mergeSel.has(site.path)) state.mergeSel.set(site.path, new Set());
    }
  } catch (err) {
    $("run-status").textContent = "";
    return reportError(err);
  }
  rebuildUnits();
}

/** Build units from cached parses + per-site merge selection, then audit + render. */
function rebuildUnits() {
  state.units = [];
  const warnings = [];

  for (const site of state.sites) {
    const sel = state.mergeSel.get(site.path) || new Set();
    const chosen = (site.parsedFiles || []).filter((pf) => sel.has(pf.name));
    const singles = (site.parsedFiles || []).filter((pf) => !sel.has(pf.name));
    if (chosen.length >= 2) {
      detectStpConflicts(chosen.map((pf) => pf.parsed), site).forEach((w) => warnings.push(w));
      const merged = mergeParsed(chosen.map((pf) => pf.parsed));
      const customName = state.mergeName.get(site.path);
      if (customName) merged.hostname = customName;
      const mu = makeUnit(site, merged, chosen.map((pf) => ({ name: pf.name, text: pf.parsed.text })));
      mu.mergedFrom = chosen.map((pf) => ({ name: pf.name, parsed: pf.parsed })); // faint source cards
      state.units.push(mu);
    } else {
      singles.push(...chosen); // a lone "merge" tick is just a single device
    }
    for (const pf of singles) {
      state.units.push(makeUnit(site, pf.parsed, [{ name: pf.name, text: pf.parsed.text }]));
    }
  }

  // Interface-map conflicts for any device whose mapping persisted from a prior build.
  for (const unit of state.units) {
    const d = deviceCfg(unit);
    if (!d.ifaceMap.size) continue;
    const selTargets = new Set([...d.ifaceSel.entries()].filter(([, v]) => v.checked).map(([n]) => n));
    detectInterfaceMapConflicts(unit.parsed, d.ifaceMap, { label: unit.id, selectedTargets: selTargets })
      .forEach((w) => warnings.push(w.message));
  }
  renderWarnings(warnings);

  // STP vlan union across the scan (for root election rewrites)
  const vlanSet = new Set();
  for (const u of state.units) {
    for (const v of u.parsed.spanningTree.vlanConfig || []) {
      for (const part of String(v.vlans).split(",")) vlanSet.add(part.trim());
    }
  }
  state.stpVlans = [...vlanSet].filter(Boolean).join(",") || null;

  computePoColors();
  renderResults();
  refreshTagMap();
  $("run-status").textContent = `Built ${state.units.length} device template${state.units.length === 1 ? "" : "s"}.`;
  $("btn-save").disabled = false;
}

/** Default name suggestion for a merged device (keep the switch's hostname). */
function defaultMergeName(site) {
  const sw = (site.parsedFiles || []).find((pf) => isSwitchParsed(pf.parsed));
  const pick = sw || (site.parsedFiles || [])[0];
  return (pick && pick.parsed.hostname) || site.name || site.path;
}

/** A site block: site header + device cards + (candidate) merge tile at the bottom. */
function renderSiteBlock(site, units) {
  const block = document.createElement("section");
  block.className = "site-block";
  const candidate = isMergeCandidate(site.parsedFiles);

  block.innerHTML =
    `<div class="site-block-head"><span class="site-name">${escapeHtml(site.path)}</span>` +
    (candidate ? `<span class="merge-flag">⚡ merge candidate</span>` : "") +
    `</div>`;

  // Seed the per-site spanning-tree root default (current root if not already chosen);
  // the actual control lives inside each switch's card (see renderUnit).
  const stpUnits = units.filter((u) => u.parsed.spanningTree.mode);
  let currentRootId = null;
  if (stpUnits.length) {
    const current = detectCurrentRoot(stpUnits);
    currentRootId = current ? current.id : null;
    const stored = state.rootBySite.get(site.path);
    const selectedId = stored && stpUnits.some((u) => u.id === stored) ? stored : currentRootId || "";
    state.rootBySite.set(site.path, selectedId);
  }

  for (const u of units) {
    block.appendChild(renderUnit(u, currentRootId));
    // A slim strip referencing the source devices merged into this one (not full cards).
    if (u.mergedFrom) block.appendChild(renderMergedFromStrip(u));
  }

  // Merge tile — styled like a device card, at the bottom of the site (candidate sites only).
  if (candidate) block.appendChild(renderMergeTile(site));
  return block;
}

/** A compact strip listing the source devices that were merged into a unit (click to view config). */
function renderMergedFromStrip(unit) {
  const strip = document.createElement("div");
  strip.className = "merged-from";
  strip.innerHTML =
    `<span class="merged-from-label">↳ merged from</span>` +
    unit.mergedFrom
      .map((src, i) => {
        const t = deviceType(src.parsed);
        return (
          `<button class="merged-chip" type="button" data-i="${i}" title="View ${escapeHtml(src.name)}">` +
          `<span class="dev-chip dev-${t}">${t}</span> ${escapeHtml(src.parsed.hostname || src.name)} ⤢</button>`
        );
      })
      .join("");
  strip.querySelectorAll(".merged-chip").forEach((btn) =>
    btn.addEventListener("click", () => {
      const src = unit.mergedFrom[Number(btn.dataset.i)];
      openConfigModal(src.parsed.hostname || src.name, [{ name: src.name, text: src.parsed.text }]);
    })
  );
  return strip;
}

/** A device-card-styled tile to select files and merge them into one named device. */
function renderMergeTile(site) {
  const committed = state.mergeSel.get(site.path) || new Set();
  const merged = committed.size >= 2;
  const tile = document.createElement("details");
  tile.className = "unit merge-tile"; // collapsed by default; selecting doesn't rebuild, so it stays open while interacting

  const files = (site.parsedFiles || [])
    .map((pf) => {
      const t = deviceType(pf.parsed);
      const checked = committed.size ? committed.has(pf.name) : true; // suggest all when not yet merged
      return (
        `<label class="merge-file"><input type="checkbox" class="merge-file-cb" data-file="${escapeHtml(pf.name)}"${checked ? " checked" : ""} />` +
        `<span class="merge-file-name">${escapeHtml(pf.name)}</span>` +
        `<span class="dev-chip dev-${t}">${t}</span>` +
        `<span class="muted small merge-file-host">${escapeHtml(pf.parsed.hostname || "")}</span></label>`
      );
    })
    .join("");
  const nameVal = state.mergeName.get(site.path) || defaultMergeName(site);

  tile.innerHTML =
    `<summary class="unit-head"><span class="unit-titlebar">` +
    `<span class="unit-site">merge</span><span class="unit-host">${escapeHtml(site.path)}</span></span>` +
    `<span class="merge-flag">⚡ router + switch → one L3 switch</span></summary>` +
    `<div class="unit-body">` +
    `<p class="muted small">Tick the devices to combine, name the merged Layer-3 switch, then click <strong>Merge</strong>. ${merged ? "Currently merged." : ""}</p>` +
    `<div class="merge-files">${files}</div>` +
    `<div class="merge-actions">` +
    `<label class="field merge-name-field"><span>Merged device name</span><input class="merge-name" type="text" value="${escapeHtml(nameVal)}" autocomplete="off" /></label>` +
    `<button class="btn btn-primary merge-go" type="button" disabled>⚒ Merge these devices</button>` +
    (merged ? `<button class="btn btn-ghost merge-undo" type="button">Unmerge</button>` : "") +
    `</div></div>`;

  const goBtn = tile.querySelector(".merge-go");
  const cbs = () => [...tile.querySelectorAll(".merge-file-cb")];
  const syncBtn = () => (goBtn.disabled = cbs().filter((c) => c.checked).length < 2);
  // selecting does NOT rebuild — the tile stays open until the user commits.
  cbs().forEach((c) => c.addEventListener("change", syncBtn));
  syncBtn();

  goBtn.addEventListener("click", () => {
    const chosen = new Set(cbs().filter((c) => c.checked).map((c) => c.dataset.file));
    if (chosen.size < 2) return;
    state.mergeSel.set(site.path, chosen);
    const name = tile.querySelector(".merge-name").value.trim();
    if (name) state.mergeName.set(site.path, name);
    else state.mergeName.delete(site.path);
    rebuildUnits();
  });
  const undo = tile.querySelector(".merge-undo");
  if (undo)
    undo.addEventListener("click", () => {
      state.mergeSel.set(site.path, new Set());
      rebuildUnits();
    });

  return tile;
}

function makeUnit(site, parsed, sources) {
  const findings = audit(parsed);
  const sourceNames = sources.map((s) => s.name);
  return {
    id: `${site.path}::${parsed.hostname || sourceNames[0]}`,
    site,
    parsed,
    sources, // [{ name, text }] — individual device configs (for per-device view)
    sourceNames,
    findings,
    output: null,
    ai: null,
  };
}

/** Best guess at which scanned switch is currently the spanning-tree root. */
function detectCurrentRoot(stpUnits) {
  let best = null;
  let bestScore = Infinity;
  let signal = false;
  for (const u of stpUnits) {
    const stp = u.parsed.spanningTree;
    const hasPrimary = (stp.vlanConfig || []).some((v) => v.root === "primary");
    const mstPrimary = (stp.mstConfig?.priorities || []).some((p) => /primary|^0$|^4096$/.test(String(p.value)));
    const prios = (stp.vlanConfig || []).map((v) => v.priority).filter((p) => typeof p === "number");
    let score;
    if (hasPrimary || mstPrimary) {
      score = -1;
      signal = true;
    } else if (prios.length) {
      score = Math.min(...prios);
      if (score < 32768) signal = true;
    } else {
      score = 32768;
    }
    if (score < bestScore) {
      bestScore = score;
      best = u;
    }
  }
  return signal ? best : null;
}

// ----------------------------------------------------------------- save

/**
 * Synthesize a default template when the user hasn't chosen one. Tag-based:
 * a hostname line plus every marker from the computed tag map under a labelled
 * comment. Direct: a minimal base — renderDirect appends the section headers.
 */
function defaultTemplate(config, hostname) {
  const host = hostname || "PLACEHOLDER";
  if (config.insertion === "direct") {
    return `!\nhostname ${host}\n!\nip routing\n!`;
  }
  const lines = ["!", `hostname ${host}`, "!", "ip routing", "!"];
  for (const slot of buildTagMap(config)) {
    const label = slot.tag === "harden" ? "hardening" : slot.label;
    lines.push(`! ---- ${label} ----`, `{${slot.tag}}`, "!");
  }
  lines.push("end");
  return lines.join("\n");
}

/** True if a device has nothing selected to collect (no interfaces, routing, or other data). */
function unitCollectsNothing(unit) {
  const d = deviceCfg(unit);
  const anyIface = d.interfacesAll.enabled || [...d.ifaceSel.values()].some((v) => v.checked);
  const anyRouting = d.routing.defaultGateway || d.routing.allStatic || d.routing.protocols;
  const anyOther = d.vrf || d.stp || d.dhcp || d.snmp || d.tacacs || d.logging || d.ntp;
  const anyHarden = unit.findings.some((f) => f.apply);
  return !anyIface && !anyRouting && !anyOther && !anyHarden;
}

function saveSanityWarnings(global, anyElectedRoot) {
  const w = [];
  const empties = state.units.filter((u) => unitCollectsNothing(u));
  if (empties.length === state.units.length) {
    w.push("no device has anything selected to collect");
  } else if (empties.length) {
    w.push(`${empties.length} device(s) have nothing selected: ${empties.map((u) => u.parsed.hostname || u.sourceNames[0]).join(", ")}`);
  }
  if (!global.secureAccess.enabled && !global.vtp.enabled && !anyElectedRoot) {
    w.push("no global additions (VTP / secure access / root election)");
  }
  return w;
}

async function onSave() {
  const global = readGlobalConfig();
  if (!state.units.length) return reportError(new Error("Scan a folder first (Step 1)."));

  const anyElectedRoot = [...state.rootBySite.values()].some(Boolean);

  // Pre-generation sanity check: if no device collects much, confirm intent.
  const sanity = saveSanityWarnings(global, anyElectedRoot);
  if (sanity.length >= 2) {
    const ok = await styledConfirm({
      title: "Your templates will be sparse",
      message: "Crucible didn’t detect much selected to put in the output:",
      items: sanity,
      confirmLabel: "Generate anyway",
      cancelLabel: "Go back",
    });
    if (!ok) {
      $("run-status").textContent = "Cancelled — nothing generated.";
      return;
    }
  }

  $("run-status").textContent = "Building & saving…";

  // Per-site current root (to tell "leave as-is" from "change root").
  const siteCurrentRoot = new Map();
  for (const u of state.units) {
    if (!u.parsed.spanningTree.mode) continue;
    if (!siteCurrentRoot.has(u.site.path)) {
      const us = state.units.filter((x) => x.site.path === u.site.path && x.parsed.spanningTree.mode);
      const c = detectCurrentRoot(us);
      siteCurrentRoot.set(u.site.path, c ? c.id : null);
    }
  }

  const zipFiles = [];
  const allWarnings = [];

  for (const unit of state.units) {
    const ucfg = unitConfig(unit, global);
    const dcfg = deviceCfg(unit);

    // Interface-map conflicts: hard ones block this unit, soft ones just warn.
    const selTargets = new Set(
      [...dcfg.ifaceSel.entries()].filter(([, v]) => v.checked).map(([n]) => n)
    );
    const mapConflicts = detectInterfaceMapConflicts(unit.parsed, dcfg.ifaceMap, {
      label: unit.id,
      selectedTargets: selTargets,
    });
    mapConflicts.forEach((w) => allWarnings.push(w.message));
    if (mapConflicts.some((w) => w.hard)) continue; // skip writing this unit

    const elected = state.rootBySite.get(unit.site.path) || null;
    const changingRoot = !!elected && elected !== siteCurrentRoot.get(unit.site.path);
    // Electing a root implies STP must be emitted for that site's switches.
    if (elected && unit.parsed.spanningTree.mode) ucfg.stp.enabled = true;
    const stpRole = !ucfg.stp.enabled
      ? "asis"
      : changingRoot
      ? unit.id === elected
        ? "root"
        : "nonroot"
      : "asis";

    const applied = unit.findings.filter((f) => f.apply);
    const hardenLines = remediationLines(applied);

    const tparsed = applyInterfaceMap(unit.parsed, dcfg.ifaceMap);
    const slots = buildBlocks(ucfg, tparsed, {
      stpRole,
      stpVlans: state.stpVlans,
      hardenLines,
    });

    const templateText =
      state.template && state.template.text
        ? state.template.text
        : defaultTemplate(ucfg, unit.parsed.hostname);

    const rendered =
      ucfg.insertion === "direct"
        ? renderDirect(templateText, slots)
        : renderTagBased(templateText, slots);

    let content = rendered.content;
    const isSwitch = isSwitchParsed(unit.parsed);
    const appendBlock = (title, lines) => {
      if (lines && lines.length) content = content.replace(/\n*$/, "") + `\n!\n! ==== ${title} ====\n${lines.join("\n")}\n`;
    };

    // Global additions injected into every output (switch-only ones gated).
    if (global.clock.enabled) appendBlock("Clock & timezone", buildClock(global.clock));
    if (global.banner.enabled) appendBlock("Banner", buildBanner(global.banner));
    if (global.stpHardening.enabled && isSwitch) appendBlock("Spanning-tree hardening", buildStpHardening());
    if (global.errdisable.enabled && isSwitch) appendBlock("Errdisable recovery", buildErrdisable(global.errdisable));

    // VTP v3 block — switch templates only (routers don't run VTP).
    if (global.vtp && global.vtp.enabled && isSwitchParsed(unit.parsed)) {
      const vtpLines = buildVtp(global.vtp);
      if (vtpLines.length) {
        content = content.replace(/\n*$/, "") + `\n!\n! ==== VTP ====\n${vtpLines.join("\n")}\n`;
      } else {
        allWarnings.push(`${unit.id}: VTP enabled but no domain name — skipped.`);
      }
    }

    // Secure access block (user-supplied hardened admin + SSH login), appended to every output.
    if (global.secureAccess && global.secureAccess.enabled) {
      const secLines = buildSecureAccess(global.secureAccess);
      if (secLines.length) {
        content = content.replace(/\n*$/, "") + `\n!\n! ==== Secure access ====\n${secLines.join("\n")}\n`;
      } else {
        allWarnings.push(`${unit.id}: secure access enabled but username/password missing — skipped.`);
      }
    }

    const naming = computeOutput(unit.parsed, global.naming);
    if (global.naming.rename) content = applyHostname(content, naming.hostname);

    rendered.warnings.forEach((w) => allWarnings.push(`${unit.id}: ${w}`));

    try {
      const filename = await writeOutput(unit, naming.filename, content, zipFiles);
      unit.output = { filename, content };
      markUnitWritten(unit, filename);
    } catch (err) {
      allWarnings.push(`${unit.id}: write failed — ${err.message}`);
    }
  }

  // Zip whenever there's no real folder handle to write into (fallback browser or sample data).
  if (zipFiles.length) {
    downloadZip(buildZip(zipFiles), "crucible-output.zip");
  }

  renderWarnings(allWarnings);
  $("run-status").textContent = `Saved ${state.units.filter((u) => u.output).length} file(s).`;
}

async function writeOutput(unit, filename, content, zipFiles) {
  if (state.mode === "primary" && unit.site.dirHandle) {
    const dir = unit.site.dirHandle;
    const finalName = await uniqueName(dir, filename);
    const fh = await dir.getFileHandle(finalName, { create: true });
    const writable = await fh.createWritable();
    await writable.write(content);
    await writable.close();
    return finalName;
  }
  // fallback: queue for the zip, mirroring the site sub-folder
  const path = `${unit.site.path}/${filename}`.replace(/^[^/]*\//, ""); // drop master root segment
  zipFiles.push({ path, content });
  return filename;
}

async function uniqueName(dir, filename) {
  const dot = filename.lastIndexOf(".");
  const base = dot > 0 ? filename.slice(0, dot) : filename;
  const ext = dot > 0 ? filename.slice(dot) : "";
  let candidate = filename;
  let n = 1;
  // getFileHandle without create throws NotFoundError when the name is free.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      await dir.getFileHandle(candidate, { create: false });
      candidate = `${base}_${n++}${ext}`; // taken → try next
    } catch {
      return candidate; // free
    }
  }
}

function downloadZip(bytes, name) {
  const blob = new Blob([bytes], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ----------------------------------------------------------------- results UI

function renderResults() {
  state.ifaceConfigs = new Map();
  const root = $("results");
  root.innerHTML = "";
  const bySite = new Map();
  for (const u of state.units) {
    if (!bySite.has(u.site.path)) bySite.set(u.site.path, { site: u.site, units: [] });
    bySite.get(u.site.path).units.push(u);
  }
  for (const { site, units } of bySite.values()) root.appendChild(renderSiteBlock(site, units));
}

const getPath = (o, path) => path.split(".").reduce((a, k) => (a == null ? a : a[k]), o);
function setPath(o, path, v) {
  const ks = path.split(".");
  const last = ks.pop();
  let t = o;
  for (const k of ks) t = t[k] || (t[k] = {});
  t[last] = v;
}

/** A fully self-contained, collapsible per-device card: header + Interfaces + Routing & services + (STP root) + Hardening. */
function renderUnit(unit, currentRootId = null) {
  const p = unit.parsed;
  const d = deviceCfg(unit);
  const card = document.createElement("details");
  card.className = "unit";
  card.dataset.unit = unit.id;

  const routingN = p.staticRoutes.length + p.protocols.length + (p.defaultGateway ? 1 : 0);
  const feats = [
    { label: `${p.interfaces.length} interfaces`, on: p.interfaces.length > 0, tip: `${p.interfaces.length} interface block(s) parsed` },
    { label: "Routing", on: routingN > 0, tip: `${p.staticRoutes.length} static route(s), ${p.protocols.length} routing protocol(s)${p.defaultGateway ? ", default gateway" : ""}` },
    { label: "VRF", on: p.vrfs.length > 0, tip: p.vrfs.length ? `VRFs: ${p.vrfs.map((v) => v.name).join(", ")}` : "No VRFs configured" },
    { label: p.spanningTree.mode ? `STP ${p.spanningTree.mode}` : "STP", on: !!p.spanningTree.mode, tip: p.spanningTree.mode ? `Spanning-tree mode ${p.spanningTree.mode}` : "No spanning-tree configured" },
    { label: "DHCP", on: p.dhcpPools.length > 0, tip: p.dhcpPools.length ? `${p.dhcpPools.length} DHCP pool(s): ${p.dhcpPools.map((x) => x.name).join(", ")}` : "No DHCP pools" },
    { label: "SNMP", on: p.snmp.length > 0, tip: p.snmp.length ? `${p.snmp.length} snmp-server line(s)` : "No SNMP config" },
    { label: "TACACS+", on: p.tacacs.length > 0, tip: p.tacacs.length ? `${p.tacacs.length} TACACS+ line(s)` : "No TACACS+ config" },
    { label: "Logging", on: p.logging.length > 0, tip: p.logging.length ? `${p.logging.length} logging line(s)` : "No logging config" },
    { label: "NTP", on: p.ntp.length > 0, tip: p.ntp.length ? `${p.ntp.length} ntp line(s)` : "No NTP config" },
  ];
  const pills = feats
    .map((f) => `<span class="feat-pill ${f.on ? "on" : "off"}" title="${escapeHtml(f.tip)}">${escapeHtml(f.label)}</span>`)
    .join("");

  const ifaces = (p.interfaces || [])
    .slice()
    .sort((a, b) => a.normName.localeCompare(b.normName, undefined, { numeric: true }));

  const COLL_GROUPS = [
    {
      name: "Routing",
      items: [
        { path: "routing.defaultGateway", label: "Default gateway → default route", has: !!p.defaultGateway },
        { path: "routing.allStatic", label: "Static routes", has: p.staticRoutes.length > 0 },
        { path: "routing.protocols", label: "Routing protocols", has: p.protocols.length > 0 },
        { path: "vrf", label: "VRFs", has: p.vrfs.length > 0 },
      ],
    },
    {
      name: "Switching",
      items: [
        { path: "stp", label: "Spanning-tree", has: !!p.spanningTree.mode },
        { path: "dhcp", label: "DHCP scopes", has: p.dhcpPools.length > 0 },
      ],
    },
    {
      name: "Management",
      items: [
        { path: "snmp", label: "SNMP", has: p.snmp.length > 0 },
        { path: "tacacs", label: "TACACS+", has: p.tacacs.length > 0 },
        { path: "logging", label: "Logging", has: p.logging.length > 0 },
        { path: "ntp", label: "NTP", has: p.ntp.length > 0 },
        { path: "dns", label: "DNS (name-server / domain)", has: p.dns.length > 0 },
      ],
    },
  ];
  const collHtml = COLL_GROUPS.map(
    (g) =>
      `<div class="coll-group"><h4 class="coll-group-head">${g.name}</h4><div class="coll-grid">` +
      g.items
        .map(
          (c) =>
            `<label class="checkbox coll-item"><input type="checkbox" class="coll-cb" data-path="${c.path}"${getPath(d, c.path) ? " checked" : ""} />` +
            `<span>${escapeHtml(c.label)}${c.has ? "" : ' <span class="muted small">(none found)</span>'}</span></label>`
        )
        .join("") +
      `</div></div>`
  ).join("");

  // Interface mapping subsection markup (between Interfaces and Routing & services).
  const siblingPorts = [
    ...new Set(
      state.units
        .filter((u) => u.site.path === unit.site.path && u.id !== unit.id)
        .flatMap((u) => (u.parsed.interfaces || []).map((f) => f.normName))
    ),
  ].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const knownVlans = [
    ...new Set((p.interfaces || []).map((f) => (f.normName.match(/^Vlan(\d+)$/i) || [])[1]).filter(Boolean)),
  ];
  const dlId = `ports-${unit.id}`;
  const vlId = `vlans-${unit.id}`;
  const mappedCount = ifaces.filter((f) => (d.ifaceMap.get(f.normName)?.target || "").trim()).length;
  const ifmapRows = ifaces
    .map((f) => {
      const m = d.ifaceMap.get(f.normName) || { target: "", transform: "routed", vlan: "" };
      const isSvi = m.transform === "svi";
      const grp = `ifmode-${unit.id}-${f.normName}`;
      return (
        `<div class="ifmap-row" data-name="${escapeHtml(f.normName)}">` +
        `<span class="ifmap-src">${escapeHtml(f.normName)}</span><span class="ifmap-arrow">→</span>` +
        `<input class="ifmap-target" list="${dlId}" placeholder="(keep name)" value="${escapeHtml(m.target || "")}" />` +
        `<label class="ifmap-mode"><input type="radio" name="${escapeHtml(grp)}" value="routed"${isSvi ? "" : " checked"} /> routed</label>` +
        `<label class="ifmap-mode"><input type="radio" name="${escapeHtml(grp)}" value="svi"${isSvi ? " checked" : ""} /> SVI</label>` +
        `<input class="ifmap-vlan${isSvi ? "" : " hidden"}" placeholder="VLAN" list="${vlId}" value="${escapeHtml(m.vlan || "")}" />` +
        `</div>`
      );
    })
    .join("");
  const ifmapHtml =
    `<details class="unit-sub"><summary class="unit-sub-head"><strong>Interface mapping</strong> ` +
    `<span class="muted small">${mappedCount} remapped</span></summary>` +
    `<p class="muted small sub-desc">Remap a source interface to a target hardware port. Blank = keep. A mapped target replaces any colliding port on this device.</p>` +
    `<div class="ifmap-rows">${ifmapRows}</div>` +
    `<datalist id="${dlId}">${siblingPorts.map((n) => `<option value="${escapeHtml(n)}">`).join("")}</datalist>` +
    `<datalist id="${vlId}">${knownVlans.map((n) => `<option value="${escapeHtml(n)}">`).join("")}</datalist>` +
    `</details>`;

  const missing = unit.findings.filter((f) => f.status === "missing");
  const pass = unit.findings.filter((f) => f.status === "pass").length;

  card.innerHTML =
    `<summary class="unit-head">` +
    `<span class="unit-caret"></span>` +
    `<span class="unit-titlebar"><span class="unit-site">${escapeHtml(unit.site.path)}</span>` +
    `<span class="unit-host">${escapeHtml(p.hostname || "(no hostname)")}</span>` +
    `<span class="unit-src muted small"> ← ${escapeHtml(unit.sourceNames.join(", "))}</span></span>` +
    `<button class="btn btn-small unit-view" type="button">⤢ view config</button>` +
    `<span class="unit-written muted small"></span></summary>` +
    `<div class="unit-body">` +
    `<div class="feat-pills">${pills}</div>` +
    // Interfaces subsection
    `<details class="unit-sub"><summary class="unit-sub-head">` +
    `<strong>Interfaces</strong> <span class="muted small">${ifaces.length} found</span>` +
    `<label class="checkbox if-all-inline"><input type="checkbox" class="d-ifall"${d.interfacesAll.enabled ? " checked" : ""} /><span>All</span></label>` +
    `<select class="d-ifall-mode"><option value="full"${d.interfacesAll.mode !== "ip" ? " selected" : ""}>All data</option><option value="ip"${d.interfacesAll.mode === "ip" ? " selected" : ""}>IP only</option></select>` +
    `<button class="btn btn-small btn-ghost d-selectall" type="button">Select all</button></summary>` +
    `<div class="disc-grid"></div></details>` +
    // Interface mapping subsection
    ifmapHtml +
    // Routing & services subsection
    `<details class="unit-sub"><summary class="unit-sub-head"><strong>Routing &amp; services</strong></summary>` +
    `<p class="muted small sub-desc">Pre-ticked with what this device actually has — untick anything you don't want carried across.</p>` +
    `<div class="coll-groups">${collHtml}</div></details>` +
    // Spanning-tree root subsection (switch devices only)
    (p.spanningTree.mode
      ? `<details class="unit-sub"><summary class="unit-sub-head"><strong>Spanning-tree root</strong>` +
        (currentRootId === unit.id ? ` <span class="feat-pill on">currently root</span>` : "") +
        `</summary><div class="stp-root-body">` +
        `<label class="checkbox"><input type="checkbox" class="root-elect" data-site="${escapeHtml(unit.site.path)}"${state.rootBySite.get(unit.site.path) === unit.id ? " checked" : ""} />` +
        `<span>Elect this switch as the spanning-tree root for its site</span></label>` +
        `<p class="muted small">Sets it as the sole root (root primary); other switches in the site stand down (root secondary). Leave unticked to carry spanning-tree across unchanged.</p>` +
        `</div></details>`
      : "") +
    // Hardening subsection
    `<details class="harden-section"><summary class="harden-head">` +
    `<strong>Hardening</strong> <span class="muted small">${pass} pass · ${missing.length} missing</span>` +
    `<label class="checkbox apply-all"><input type="checkbox" class="apply-all-cb" /><span>Apply all</span></label>` +
    `<button class="btn btn-small ai-btn" type="button">AI review</button></summary>` +
    `<p class="harden-desc">Best-practice hardening checks — tick the missing items to inject into this device's template. Tailored to router vs switch.</p>` +
    `<div class="findings"></div><div class="ai-out"></div></details>` +
    `</div>`;

  // --- interfaces ---
  const grid = card.querySelector(".disc-grid");
  for (const f of ifaces) grid.appendChild(buildIfaceTile(unit, f));
  if (d.interfacesAll.enabled) grid.classList.add("inert");
  const ifAll = card.querySelector(".d-ifall");
  const ifAllMode = card.querySelector(".d-ifall-mode");
  const applyIfAll = () => {
    d.interfacesAll = { enabled: ifAll.checked, mode: ifAllMode.value };
    grid.classList.toggle("inert", ifAll.checked);
    refreshTagMap();
  };
  ifAll.addEventListener("change", applyIfAll);
  ifAllMode.addEventListener("change", applyIfAll);
  const selAll = card.querySelector(".d-selectall");
  selAll.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const tiles = [...grid.querySelectorAll(".disc-if-cb")];
    const allOn = tiles.length && tiles.every((c) => c.checked);
    tiles.forEach((c) => {
      c.checked = !allOn;
      c.dispatchEvent(new Event("change"));
    });
    selAll.textContent = allOn ? "Select all" : "Clear all";
  });
  card.querySelectorAll(".if-all-inline, .d-ifall-mode").forEach((el) =>
    el.addEventListener("click", (e) => e.stopPropagation())
  );

  // --- interface mapping ---
  const ifmapCount = card.querySelector(".unit-sub .ifmap-rows")?.closest(".unit-sub")?.querySelector(".unit-sub-head .muted");
  const refreshMapCount = () => {
    if (!ifmapCount) return;
    const n = [...d.ifaceMap.values()].filter((m) => (m.target || "").trim()).length;
    ifmapCount.textContent = `${n} remapped`;
  };
  card.querySelectorAll(".ifmap-row").forEach((row) => {
    const name = row.dataset.name;
    // Rich hover: reuse the interface-config tooltip (populated by buildIfaceTile).
    const tipKey = `${unit.id}::${name}`;
    const srcEl = row.querySelector(".ifmap-src");
    srcEl.addEventListener("mouseenter", () => showIfaceTip(tipKey, srcEl));
    srcEl.addEventListener("mouseleave", hideIfaceTip);
    const get = () => d.ifaceMap.get(name) || { target: "", transform: "routed", vlan: "" };
    const set = (patch) => {
      d.ifaceMap.set(name, { ...get(), ...patch });
      refreshMapCount();
      refreshTagMap();
    };
    const targetIn = row.querySelector(".ifmap-target");
    const vlanIn = row.querySelector(".ifmap-vlan");
    targetIn.addEventListener("input", () => set({ target: targetIn.value }));
    vlanIn.addEventListener("input", () => set({ vlan: vlanIn.value }));
    row.querySelectorAll("input[type=radio]").forEach((r) =>
      r.addEventListener("change", () => {
        const svi = row.querySelector("input[value=svi]").checked;
        vlanIn.classList.toggle("hidden", !svi);
        set({ transform: svi ? "svi" : "routed" });
      })
    );
  });

  // --- routing & services ---
  card.querySelectorAll(".coll-cb").forEach((cb) =>
    cb.addEventListener("change", () => {
      setPath(d, cb.dataset.path, cb.checked);
      refreshTagMap();
    })
  );

  // --- hardening ---
  const findingsEl = card.querySelector(".findings");
  for (const f of unit.findings) findingsEl.appendChild(renderFinding(unit, f));
  const applyAll = card.querySelector(".apply-all-cb");
  applyAll.addEventListener("click", (e) => e.stopPropagation());
  applyAll.addEventListener("change", (e) => {
    for (const f of unit.findings) if (f.status === "missing") f.apply = e.target.checked;
    card.querySelectorAll(".finding-apply").forEach((cb) => {
      if (!cb.disabled) cb.checked = e.target.checked;
    });
  });
  const aiBtn = card.querySelector(".ai-btn");
  aiBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    card.querySelector(".harden-section").open = true;
    runAiReview(unit, card);
  });

  // --- spanning-tree root (per site, mutually exclusive across the site's switch cards) ---
  const rootCb = card.querySelector(".root-elect");
  if (rootCb) {
    rootCb.addEventListener("change", () => {
      if (rootCb.checked) {
        state.rootBySite.set(unit.site.path, unit.id);
        document.querySelectorAll(".root-elect").forEach((o) => {
          if (o !== rootCb && o.dataset.site === unit.site.path) o.checked = false;
        });
      } else if (state.rootBySite.get(unit.site.path) === unit.id) {
        state.rootBySite.set(unit.site.path, "");
      }
    });
  }

  // --- view config ---
  card.querySelector(".unit-view").addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    openConfigModal(p.hostname || unit.sourceNames[0], unit.sources);
  });

  return card;
}

// ----------------------------------------------------------------- config modal

let modalText = "";

/** Open the config modal. `sources` = [{ name, text }] — multiple gives per-device tabs. */
function openConfigModal(title, sources) {
  state.modalSources = sources && sources.length ? sources : [{ name: "", text: "" }];
  $("cfg-modal-title").textContent = title || "Device config";

  const tabs = $("cfg-tabs");
  if (state.modalSources.length > 1) {
    tabs.innerHTML = state.modalSources
      .map((s, i) => `<button class="cfg-tab${i === 0 ? " active" : ""}" type="button" data-i="${i}">${escapeHtml(s.name)}</button>`)
      .join("");
    tabs.classList.remove("hidden");
  } else {
    tabs.innerHTML = "";
    tabs.classList.add("hidden");
  }
  showModalSource(0);

  const copyBtn = $("cfg-copy");
  copyBtn.textContent = "Copy code";
  copyBtn.classList.remove("copied");
  const modal = $("cfg-modal");
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function showModalSource(i) {
  const s = state.modalSources[i] || { name: "", text: "" };
  modalText = s.text || "";
  $("cfg-modal-sub").textContent = s.name ? `source: ${s.name}` : "";
  $("cfg-code").textContent = modalText;
  $("cfg-tabs")
    .querySelectorAll(".cfg-tab")
    .forEach((b) => b.classList.toggle("active", Number(b.dataset.i) === i));
}

function closeConfigModal() {
  const modal = $("cfg-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

/** Promise-based styled confirm dialog (replaces window.confirm). Resolves true/false. */
function styledConfirm({ title, message, items = [], confirmLabel = "Confirm", cancelLabel = "Cancel" }) {
  return new Promise((resolve) => {
    const modal = $("confirm-modal");
    $("confirm-title-text").textContent = title;
    $("confirm-message").textContent = message;
    const list = $("confirm-list");
    list.innerHTML = items.map((i) => `<li>${escapeHtml(i)}</li>`).join("");
    list.classList.toggle("hidden", !items.length);
    const okBtn = $("confirm-ok");
    okBtn.textContent = confirmLabel;
    $("confirm-cancel").textContent = cancelLabel;
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");

    const cleanup = (result) => {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      okBtn.removeEventListener("click", onOk);
      modal.removeEventListener("click", onCancel);
      document.removeEventListener("keydown", onKey);
      resolve(result);
    };
    const onOk = () => cleanup(true);
    const onCancel = (e) => {
      if (e.target.hasAttribute("data-confirm-cancel")) cleanup(false);
    };
    const onKey = (e) => {
      if (e.key === "Escape") cleanup(false);
      else if (e.key === "Enter") cleanup(true);
    };
    okBtn.addEventListener("click", onOk);
    modal.addEventListener("click", onCancel);
    document.addEventListener("keydown", onKey);
    okBtn.focus();
  });
}

async function copyModalConfig() {
  const btn = $("cfg-copy");
  try {
    await navigator.clipboard.writeText(modalText);
  } catch {
    // fallback for browsers without clipboard API
    const ta = document.createElement("textarea");
    ta.value = modalText;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch { /* ignore */ }
    ta.remove();
  }
  btn.textContent = "✓ Copied";
  btn.classList.add("copied");
  setTimeout(() => {
    btn.textContent = "Copy code";
    btn.classList.remove("copied");
  }, 1600);
}

function renderFinding(unit, f) {
  const sev = `<span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>`;
  const title =
    `<span class="finding-title">${escapeHtml(f.title)}` +
    (f.detail ? ` <span class="muted small">— ${escapeHtml(f.detail)}</span>` : "") +
    `</span>`;

  const tip = f.why ? ` title="${escapeHtml(f.why)}"` : "";

  // Missing findings expand to show the remediation config they'd inject.
  if (f.status === "missing" && f.remediation.length) {
    const row = document.createElement("details");
    row.className = "finding finding-missing";
    row.innerHTML =
      `<summary class="finding-sum"${tip}>` +
      `<input type="checkbox" class="finding-apply" title="Apply remediation" />` +
      `<span class="status status-missing">missing</span>${sev}${title}` +
      `<span class="finding-caret">▸</span></summary>` +
      `<pre class="finding-rem">${escapeHtml(f.remediation.join("\n"))}</pre>`;
    const cb = row.querySelector(".finding-apply");
    cb.checked = !!f.apply;
    cb.addEventListener("click", (e) => e.stopPropagation()); // checkbox shouldn't toggle the row
    cb.addEventListener("change", (e) => (f.apply = e.target.checked));
    return row;
  }

  // Pass / N-A — simple, non-expandable row.
  const row = document.createElement("div");
  row.className = `finding finding-row finding-${f.status}`;
  if (f.why) row.title = f.why;
  row.innerHTML =
    `<span class="apply-spacer"></span><span class="status status-${f.status}">${f.status}</span>${sev}${title}<span></span>`;
  return row;
}

function markUnitWritten(unit, filename) {
  const card = document.querySelector(`.unit[data-unit="${cssEscape(unit.id)}"]`);
  if (card) card.querySelector(".unit-written").textContent = `✓ ${filename}`;
}

async function runAiReview(unit, card) {
  const out = card.querySelector(".ai-out");
  out.innerHTML = `<p class="muted small">Requesting AI review…</p>`;
  try {
    const res = await fetch("/api/harden", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(redactForAI(unit.parsed)),
    });
    const data = await res.json();
    unit.ai = data;
    if (!data.findings || !data.findings.length) {
      out.innerHTML = `<p class="muted small ai-note">${escapeHtml(data.notes || "No additional AI findings.")}</p>`;
      return;
    }
    out.innerHTML =
      `<p class="ai-label">AI advisory (not auto-applied):</p>` +
      data.findings
        .map(
          (f) =>
            `<div class="ai-finding"><span class="sev sev-${String(f.severity).toLowerCase()}">${escapeHtml(f.severity)}</span>` +
            `<strong>${escapeHtml(f.title)}</strong><div class="muted small">${escapeHtml(f.rationale || "")}</div>` +
            (f.suggestedConfig ? `<pre>${escapeHtml(f.suggestedConfig)}</pre>` : "") +
            `</div>`
        )
        .join("") +
      (data.notes ? `<p class="muted small ai-note">${escapeHtml(data.notes)}</p>` : "");
  } catch (err) {
    out.innerHTML = `<p class="muted small">AI review unavailable: ${escapeHtml(err.message)}</p>`;
  }
}

// ----------------------------------------------------------------- warnings

function renderWarnings(list) {
  const el = $("warnings");
  el.innerHTML = "";
  if (!list.length) return;
  el.innerHTML =
    `<p class="warn-title">${list.length} warning${list.length === 1 ? "" : "s"}:</p>` +
    `<ul>${list.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`;
}

// ----------------------------------------------------------------- utilities

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function cssEscape(s) {
  return (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\]/g, "\\$&");
}
function reportError(err) {
  console.error(err);
  $("warnings").innerHTML = `<p class="warn-title">Error: ${escapeHtml(err.message || String(err))}</p>`;
}

// ----------------------------------------------------------------- init

function init() {
  detectMode();
  try {
    applyTheme(localStorage.getItem("crucible-theme") || "light");
  } catch {
    applyTheme("light");
  }
  $("theme-toggle").addEventListener("click", toggleTheme);
  $("btn-sample").addEventListener("click", loadSampleData);
  $("btn-clear").addEventListener("click", clearAll);
  $("cfg-copy").addEventListener("click", copyModalConfig);
  $("cfg-tabs").addEventListener("click", (e) => {
    const b = e.target.closest(".cfg-tab");
    if (b) showModalSource(Number(b.dataset.i));
  });
  $("cfg-modal").addEventListener("click", (e) => {
    if (e.target.hasAttribute("data-close")) closeConfigModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("cfg-modal").classList.contains("hidden")) closeConfigModal();
  });
  $("btn-browse").addEventListener("click", onBrowse);
  $("fallback-input").addEventListener("change", onFallbackPicked);
  $("btn-template").addEventListener("click", onChooseTemplateFSA);
  $("template-input").addEventListener("change", onTemplatePicked);
  $("btn-clear-template").addEventListener("click", onClearTemplate);
  $("btn-save").addEventListener("click", onSave);

  // Global additions affect every device's template → refresh the tag-map preview.
  $("sec-enable").addEventListener("change", () =>
    $("sec-rows").classList.toggle("hidden", !$("sec-enable").checked)
  );
  $("vtp-enable").addEventListener("change", () =>
    $("vtp-rows").classList.toggle("hidden", !$("vtp-enable").checked)
  );
  $("errd-enable").addEventListener("change", () =>
    $("errd-rows").classList.toggle("hidden", !$("errd-enable").checked)
  );
  $("clock-enable").addEventListener("change", () =>
    $("clock-rows").classList.toggle("hidden", !$("clock-enable").checked)
  );
  $("banner-enable").addEventListener("change", () =>
    $("banner-rows").classList.toggle("hidden", !$("banner-enable").checked)
  );
  document.querySelectorAll(".secret-toggle").forEach((btn) =>
    btn.addEventListener("click", () => {
      const inp = $(btn.dataset.target);
      const reveal = inp.type === "password";
      inp.type = reveal ? "text" : "password";
      btn.textContent = reveal ? "🙈" : "👁";
      btn.setAttribute("aria-label", reveal ? "Hide" : "Show");
    })
  );
  document.querySelectorAll('input[name="insertion"]').forEach((el) => el.addEventListener("change", refreshTagMap));
  $("rename").addEventListener("change", () => $("rename-rows").classList.toggle("hidden", !$("rename").checked));

  refreshTagMap();
}

init();
