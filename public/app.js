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
} from "./lib/template.js";
import { redactForAI } from "./lib/redact.js";
import { buildZip } from "./lib/zip.js";

const CONFIG_EXT = /\.(txt|cfg)$/i;
const isConfigFile = (name) => CONFIG_EXT.test(name);

const state = {
  mode: null, // 'primary' | 'fallback'
  rootHandle: null,
  sites: [], // { path, name, dirHandle?, files: [{ name, handle? | file? }] }
  units: [], // analyzed output units (see analyze())
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
  const list = $("sites-list");
  list.innerHTML = "";
  if (!state.sites.length) {
    $("sites-summary").textContent = "No sites found — no folder directly contains a .txt/.cfg file.";
    $("btn-analyze").disabled = true;
    return;
  }
  const fileTotal = state.sites.reduce((n, s) => n + s.files.length, 0);
  $("sites-summary").textContent =
    `${state.sites.length} site${state.sites.length === 1 ? "" : "s"} · ${fileTotal} config file${fileTotal === 1 ? "" : "s"}.`;
  for (const site of state.sites) {
    const wrap = document.createElement("div");
    wrap.className = "site";
    const names = site.files.map((f) => `<li>${escapeHtml(f.name)}</li>`).join("");
    wrap.innerHTML =
      `<div class="site-head"><span class="site-path">${escapeHtml(site.path)}</span>` +
      `<span class="site-count">${site.files.length} file${site.files.length === 1 ? "" : "s"}</span></div>` +
      `<ul class="site-files">${names}</ul>`;
    list.appendChild(wrap);
  }
  $("btn-analyze").disabled = false;
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

/** Shared collection settings (interface picks are resolved per-device, see unitConfig). */
function readConfig() {
  const manualInterfaces = [...document.querySelectorAll(".iface-row")]
    .map((r) => ({ name: r.querySelector(".if-name").value.trim(), mode: r.querySelector(".if-mode").value }))
    .filter((i) => i.name);
  return {
    sourceCount: Math.max(1, Number($("source-count").value) || 1),
    merge: $("merge").checked,
    interfacesAll: { enabled: $("if-all").checked, mode: $("if-all-mode").value },
    manualInterfaces,
    routing: {
      defaultGateway: $("r-default").checked,
      allStatic: $("r-static").checked,
      protocols: $("r-protocols").checked,
    },
    vrf: { enabled: $("c-vrf").checked },
    stp: { enabled: $("c-stp").checked },
    dhcp: { enabled: $("c-dhcp").checked },
    snmp: { enabled: $("c-snmp").checked },
    tacacs: { enabled: $("c-tacacs").checked },
    logging: { enabled: $("c-logging").checked },
    ntp: { enabled: $("c-ntp").checked },
    secureAccess: {
      enabled: $("sec-enable").checked,
      username: $("sec-user").value.trim(),
      password: $("sec-pass").value.trim(),
      enableSecret: $("sec-enable-secret").value.trim(),
      configKey: $("sec-configkey").value.trim(),
    },
    insertion: document.querySelector('input[name="insertion"]:checked').value,
    naming: {
      rename: $("rename").checked,
      method: $("rename-method").value,
      find: $("rename-find").value,
      replace: $("rename-replace").value,
    },
  };
}

/** Interfaces ticked under a specific device in the grouped picker. */
function unitInterfaces(unitId) {
  return [...document.querySelectorAll(".disc-if")]
    .filter((t) => t.dataset.unit === unitId && t.querySelector(".disc-if-cb").checked)
    .map((t) => ({ name: t.dataset.name, mode: t.querySelector(".disc-if-mode").value }));
}

/** Per-device config: this device's ticked interfaces + global manual rows (or all). */
function unitConfig(unit, cfg) {
  const interfaces = cfg.interfacesAll.enabled
    ? []
    : dedupInterfaces([...unitInterfaces(unit.id), ...cfg.manualInterfaces]);
  return { ...cfg, interfaces };
}

function refreshTagMap() {
  const cfg = readConfig();
  const rep = state.units[0];
  const tagCfg = rep
    ? unitConfig(rep, cfg)
    : { ...cfg, interfaces: cfg.interfacesAll.enabled ? [] : dedupInterfaces(cfg.manualInterfaces) };
  const slots = buildTagMap(tagCfg);
  const el = $("tagmap");
  el.innerHTML = "";
  if (rep && !cfg.interfacesAll.enabled && state.units.length > 1) {
    const note = document.createElement("p");
    note.className = "muted small";
    note.textContent = `Interface tags shown for ${rep.parsed.hostname || rep.sourceNames[0]}; each device's auto-template is generated to match its own selection.`;
    el.appendChild(note);
  }
  for (const slot of slots) {
    const div = document.createElement("div");
    div.className = "tag-entry";
    div.innerHTML = `<span class="tag-marker">{${slot.tag}}</span><span class="tag-label">${escapeHtml(slot.label)}</span>`;
    el.appendChild(div);
  }
}

/** Populate the interface picker, grouped per device, with shutdown highlight + hover config. */
function renderDiscoveredInterfaces() {
  const box = $("disc-ifaces");
  // preserve selections across re-render, keyed by device + interface
  const prev = new Map();
  for (const t of document.querySelectorAll(".disc-if")) {
    prev.set(`${t.dataset.unit}::${t.dataset.name}`, {
      checked: t.querySelector(".disc-if-cb").checked,
      mode: t.querySelector(".disc-if-mode").value,
    });
  }
  state.ifaceConfigs = new Map(); // `${unitId}::${normName}` -> { text, host, shutdown }

  if (!state.units.length) {
    box.innerHTML = `<p class="muted small">No interfaces found in the scanned sources.</p>`;
    return;
  }
  box.innerHTML = "";
  for (const u of state.units) {
    const ifaces = (u.parsed.interfaces || [])
      .slice()
      .sort((a, b) => a.normName.localeCompare(b.normName, undefined, { numeric: true }));
    const host = u.parsed.hostname || u.sourceNames[0];

    const group = document.createElement("div");
    group.className = "dev-group";
    group.innerHTML =
      `<div class="dev-group-head"><span class="dev-name">${escapeHtml(host)}</span>` +
      `<span class="muted small">${escapeHtml(u.site.path)} · ${ifaces.length} interface${ifaces.length === 1 ? "" : "s"}</span></div>`;
    const grid = document.createElement("div");
    grid.className = "disc-grid";

    for (const f of ifaces) {
      const key = `${u.id}::${f.normName}`;
      state.ifaceConfigs.set(key, {
        text: f.text || (f.block || []).join("\n"),
        host,
        shutdown: !!f.shutdown,
      });
      const p = prev.get(key) || {};
      const tile = document.createElement("div");
      tile.className = "disc-if" + (f.shutdown ? " shutdown" : "");
      tile.dataset.unit = u.id;
      tile.dataset.name = f.normName;
      tile.innerHTML =
        `<label class="disc-if-main"><input type="checkbox" class="disc-if-cb"${p.checked ? " checked" : ""} />` +
        `<span class="disc-if-name">${escapeHtml(f.normName)}</span></label>` +
        `<div class="disc-if-row2">${f.shutdown ? '<span class="disc-if-shut">SHUT</span>' : "<span></span>"}` +
        `<select class="disc-if-mode"><option value="full"${p.mode !== "ip" ? " selected" : ""}>All data</option>` +
        `<option value="ip"${p.mode === "ip" ? " selected" : ""}>IP only</option></select></div>`;
      tile.querySelectorAll("input,select").forEach((el) => el.addEventListener("input", refreshTagMap));
      tile.addEventListener("mouseenter", () => showIfaceTip(key, tile));
      tile.addEventListener("mouseleave", hideIfaceTip);
      grid.appendChild(tile);
    }
    group.appendChild(grid);
    box.appendChild(group);
  }
  applyIfAllDisabled();
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

/** When "All interfaces" is on, the individual picker and manual rows are inert. */
function applyIfAllDisabled() {
  const off = $("if-all").checked;
  $("disc-ifaces").classList.toggle("inert", off);
  $("iface-rows").classList.toggle("inert", off);
  document
    .querySelectorAll(".disc-if-cb, .disc-if-mode, .if-name, .if-mode")
    .forEach((el) => (el.disabled = off));
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
  const names = ["Paisley Router.txt", "Paisley L3 Switch.txt"];
  $("sites-summary").textContent = "Loading sample data…";
  try {
    const files = [];
    for (const name of names) {
      const res = await fetch(`/sample-data/${encodeURIComponent(name)}`);
      if (!res.ok) throw new Error(`could not load ${name} (${res.status})`);
      files.push({ name, text: await res.text() });
    }
    state.rootHandle = null;
    state.sites = [{ path: "Paisley (sample)", name: "Paisley", files }];
    $("folder-name").textContent = "Paisley (sample data)";
    renderSites(); // auto-analyzes
  } catch (err) {
    reportError(err);
  }
}

function clearAll() {
  state.rootHandle = null;
  state.sites = [];
  state.units = [];
  state.template = null;
  state.ifaceConfigs = new Map();
  state.stpVlans = null;
  $("folder-name").textContent = "";
  $("sites-summary").textContent = "No folder selected yet.";
  $("sites-list").innerHTML = "";
  $("results").innerHTML = "";
  $("disc-ifaces").innerHTML = `<p class="muted small">Scan a folder in Step 1 and the interfaces found in each device appear here.</p>`;
  $("iface-rows").innerHTML = "";
  $("template-name").textContent = "Using auto-generated template";
  $("template-input").value = "";
  $("btn-clear-template").classList.add("hidden");
  $("stp-root-wrap").classList.add("hidden");
  $("warnings").innerHTML = "";
  $("run-status").textContent = "";
  $("if-all").checked = false;
  $("btn-analyze").disabled = true;
  $("btn-save").disabled = true;
  applyIfAllDisabled();
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

async function onAnalyze() {
  const config = readConfig();
  if (!state.sites.length) return;
  $("run-status").textContent = "Analyzing…";
  $("warnings").innerHTML = "";
  state.units = [];
  const analysisWarnings = [];

  try {
    for (const site of state.sites) {
      // File-count mismatch → flag, but still process (§10).
      if (site.files.length !== config.sourceCount) {
        analysisWarnings.push(
          `${site.path}: found ${site.files.length} config file(s), expected ${config.sourceCount}.`
        );
      }
      const parsedList = [];
      for (const entry of site.files) {
        const text = await readEntryText(entry);
        parsedList.push({ entry, parsed: parse(text) });
      }
      if (config.merge) {
        const list = parsedList.map((p) => p.parsed);
        detectStpConflicts(list, site).forEach((w) => analysisWarnings.push(w));
        const merged = mergeParsed(list);
        state.units.push(makeUnit(site, merged, site.files.map((f) => f.name)));
      } else {
        for (const { entry, parsed } of parsedList) {
          state.units.push(makeUnit(site, parsed, [entry.name]));
        }
      }
    }
  } catch (err) {
    $("run-status").textContent = "";
    return reportError(err);
  }
  renderWarnings(analysisWarnings);

  // STP vlan union across the scan (for root election rewrites)
  const vlanSet = new Set();
  for (const u of state.units) {
    for (const v of u.parsed.spanningTree.vlanConfig || []) {
      for (const part of String(v.vlans).split(",")) vlanSet.add(part.trim());
    }
  }
  state.stpVlans = [...vlanSet].filter(Boolean).join(",") || null;

  renderDiscoveredInterfaces();
  populateStpRoot(config);
  renderResults(config);
  $("run-status").textContent = `Analyzed ${state.units.length} device template${state.units.length === 1 ? "" : "s"}.`;
  $("btn-save").disabled = false;
}

function makeUnit(site, parsed, sourceNames) {
  const findings = audit(parsed);
  return {
    id: `${site.path}::${parsed.hostname || sourceNames[0]}`,
    site,
    parsed,
    sourceNames,
    findings,
    output: null,
    ai: null,
  };
}

function populateStpRoot(config) {
  const wrap = $("stp-root-wrap");
  const sel = $("stp-root");
  const stpUnits = state.units.filter((u) => config.stp.enabled && u.parsed.spanningTree.mode);
  if (stpUnits.length < 1) {
    wrap.classList.add("hidden");
    return;
  }
  wrap.classList.remove("hidden");
  sel.innerHTML = `<option value="">— none / leave as-is —</option>`;
  for (const u of stpUnits) {
    const label = `${u.parsed.hostname || u.sourceNames[0]} (${u.site.path})`;
    sel.innerHTML += `<option value="${escapeHtml(u.id)}">${escapeHtml(label)}</option>`;
  }
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

async function onSave() {
  const config = readConfig();
  if (!state.units.length) return reportError(new Error("Run Analyze first."));

  $("run-status").textContent = "Building & saving…";
  const electedRoot = $("stp-root").value || null;
  const zipFiles = [];
  const allWarnings = [];

  for (const unit of state.units) {
    const stpRole = !config.stp.enabled
      ? "asis"
      : unit.id === electedRoot
      ? "root"
      : electedRoot
      ? "nonroot"
      : "asis";

    const applied = unit.findings.filter((f) => f.apply);
    const hardenLines = remediationLines(applied);

    const ucfg = unitConfig(unit, config);
    const slots = buildBlocks(ucfg, unit.parsed, {
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

    // Secure access block (user-supplied hardened admin + SSH login), appended to every output.
    if (config.secureAccess && config.secureAccess.enabled) {
      const secLines = buildSecureAccess(config.secureAccess);
      if (secLines.length) {
        content = content.replace(/\n*$/, "") + `\n!\n! ==== Secure access ====\n${secLines.join("\n")}\n`;
      } else {
        allWarnings.push(`${unit.id}: secure access enabled but username/password missing — skipped.`);
      }
    }

    const naming = computeOutput(unit.parsed, config.naming);
    if (config.naming.rename) content = applyHostname(content, naming.hostname);

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

function renderResults(config) {
  const root = $("results");
  root.innerHTML = "";
  for (const unit of state.units) {
    root.appendChild(renderUnit(unit, config));
  }
}

function renderUnit(unit, config) {
  const p = unit.parsed;
  const card = document.createElement("div");
  card.className = "unit";
  card.dataset.unit = unit.id;

  const counts = [
    `${p.interfaces.length} interfaces`,
    `${p.staticRoutes.length} routes`,
    `${p.vrfs.length} VRFs`,
    `${p.dhcpPools.length} DHCP pools`,
    p.spanningTree.mode ? `STP ${p.spanningTree.mode}` : "no STP",
  ].join(" · ");

  const services = [
    p.snmp.length ? `SNMP ×${p.snmp.length}` : null,
    p.tacacs.length ? `TACACS+ ×${p.tacacs.length}` : null,
    p.logging.length ? `logging ×${p.logging.length}` : null,
    p.ntp.length ? `NTP ×${p.ntp.length}` : null,
  ].filter(Boolean);
  const servicesLine = services.length ? services.join(" · ") : "no SNMP / TACACS+ / logging / NTP found";

  const missing = unit.findings.filter((f) => f.status === "missing");
  const pass = unit.findings.filter((f) => f.status === "pass").length;

  card.innerHTML =
    `<div class="unit-head">` +
    `<button class="unit-title" type="button" title="View full config">` +
    `<span class="unit-host">${escapeHtml(p.hostname || "(no hostname)")}</span>` +
    `<span class="unit-src muted small"> ← ${escapeHtml(unit.sourceNames.join(", "))}</span>` +
    `<span class="unit-view-hint">⤢ view config</span></button>` +
    `<span class="unit-written muted small"></span></div>` +
    `<p class="muted small">${escapeHtml(counts)}</p>` +
    `<p class="muted small svc-line">Services: ${escapeHtml(servicesLine)}</p>` +
    `<div class="harden-head"><strong>Hardening</strong> <span class="muted small">${pass} pass · ${missing.length} missing</span>` +
    `<label class="checkbox apply-all"><input type="checkbox" class="apply-all-cb" /><span>Apply all</span></label>` +
    `<button class="btn btn-small ai-btn" type="button">AI review</button></div>` +
    `<p class="harden-desc">Best-practice hardening checks for this device — tick the missing items you want injected into its template. Suggestions are tailored to whether it’s a router or a switch.</p>` +
    `<div class="findings"></div><div class="ai-out"></div>`;

  const findingsEl = card.querySelector(".findings");
  for (const f of unit.findings) {
    findingsEl.appendChild(renderFinding(unit, f));
  }
  card.querySelector(".apply-all-cb").addEventListener("change", (e) => {
    for (const f of unit.findings) {
      if (f.status === "missing") f.apply = e.target.checked;
    }
    card.querySelectorAll(".finding-apply").forEach((cb) => {
      if (!cb.disabled) cb.checked = e.target.checked;
    });
  });
  card.querySelector(".ai-btn").addEventListener("click", () => runAiReview(unit, card));

  // Whole card is a clickable tile → opens the full-config modal. Interactive
  // controls (checkboxes, buttons, selects, the findings list) are excluded.
  card.classList.add("clickable");
  const openModal = () =>
    openConfigModal(p.hostname || unit.sourceNames[0], unit.sourceNames.join(", "), unit.parsed.text);
  card.querySelector(".unit-title").addEventListener("click", (e) => {
    e.stopPropagation();
    openModal();
  });
  card.addEventListener("click", (e) => {
    if (e.target.closest("input, select, button, label, a, .findings, .ai-out")) return;
    openModal();
  });
  return card;
}

// ----------------------------------------------------------------- config modal

let modalText = "";

function openConfigModal(title, subtitle, text) {
  modalText = text || "";
  $("cfg-modal-title").textContent = title || "Device config";
  $("cfg-modal-sub").textContent = subtitle ? `source: ${subtitle}` : "";
  $("cfg-code").textContent = modalText;
  const copyBtn = $("cfg-copy");
  copyBtn.textContent = "Copy code";
  copyBtn.classList.remove("copied");
  const modal = $("cfg-modal");
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeConfigModal() {
  const modal = $("cfg-modal");
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
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
  const row = document.createElement("div");
  row.className = `finding finding-${f.status}`;
  const sev = `<span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>`;
  const apply =
    f.status === "missing"
      ? `<input type="checkbox" class="finding-apply" title="Apply remediation" />`
      : `<span class="apply-spacer"></span>`;
  row.innerHTML =
    `${apply}<span class="status status-${f.status}">${f.status}</span>${sev}` +
    `<span class="finding-title">${escapeHtml(f.title)}${f.detail ? ` <span class="muted small">— ${escapeHtml(f.detail)}</span>` : ""}</span>`;
  const cb = row.querySelector(".finding-apply");
  if (cb) cb.addEventListener("change", (e) => (f.apply = e.target.checked));
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
  $("cfg-modal").addEventListener("click", (e) => {
    if (e.target.hasAttribute("data-close")) closeConfigModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("cfg-modal").classList.contains("hidden")) closeConfigModal();
  });
  $("btn-browse").addEventListener("click", onBrowse);
  $("fallback-input").addEventListener("change", onFallbackPicked);
  $("btn-add-iface").addEventListener("click", () => addInterfaceRow());
  $("btn-template").addEventListener("click", onChooseTemplateFSA);
  $("template-input").addEventListener("change", onTemplatePicked);
  $("btn-clear-template").addEventListener("click", onClearTemplate);
  $("btn-analyze").addEventListener("click", onAnalyze);
  $("btn-save").addEventListener("click", onSave);

  // live tag map + conditional UI
  [
    "source-count", "merge", "r-default", "r-static", "r-protocols",
    "c-vrf", "c-stp", "c-dhcp", "c-snmp", "c-tacacs", "c-logging", "c-ntp",
  ].forEach((id) => $(id).addEventListener("input", refreshTagMap));
  $("sec-enable").addEventListener("change", () =>
    $("sec-rows").classList.toggle("hidden", !$("sec-enable").checked)
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
  $("if-all").addEventListener("change", () => {
    applyIfAllDisabled();
    refreshTagMap();
  });
  $("if-all-mode").addEventListener("input", refreshTagMap);
  $("merge").addEventListener("change", () => {
    $("role-rows").classList.toggle("hidden", !$("merge").checked || Number($("source-count").value) < 2);
  });
  $("source-count").addEventListener("input", () => {
    $("role-rows").classList.toggle("hidden", !$("merge").checked || Number($("source-count").value) < 2);
  });
  $("rename").addEventListener("change", () => $("rename-rows").classList.toggle("hidden", !$("rename").checked));

  refreshTagMap();
}

init();
