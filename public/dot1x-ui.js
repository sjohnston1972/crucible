/* 802.1X implementation check — the section at the bottom of the page.
 *
 * Stands on its own folder of Catalyst 9000 backups; nothing from the run at
 * the top is used. The settings panel here is also what the main flow reads
 * when "Add 802.1X to switch outputs" is ticked (readDot1xSettings).
 */

import { parse } from "./lib/parser.js";
import { buildZip } from "./lib/zip.js";
import {
  validateSettings,
  qualifyingPorts,
  checkDot1x,
  changesText,
  applyDot1x,
  STYLE_LABEL,
} from "./lib/dot1x.js";

const $ = (id) => document.getElementById(id);

const SETTING_IDS = [
  "dx-style", "dx-mode", "dx-order", "dx-s1-name", "dx-s1-ip", "dx-key", "dx-s2-name", "dx-s2-ip", "dx-group",
  "dx-auth-port", "dx-acct-port", "dx-source", "dx-probe", "dx-coa-key", "dx-coa", "dx-host-mode", "dx-tx",
  "dx-critical", "dx-reauth", "dx-critical-voice", "dx-skip",
];

/** The settings panel as a plain object (lib/dot1x.js normalises and validates it). */
export function readDot1xSettings() {
  return {
    style: $("dx-style").value,
    mode: $("dx-mode").value,
    order: $("dx-order").value,
    server1Name: $("dx-s1-name").value,
    server1Ip: $("dx-s1-ip").value,
    server2Name: $("dx-s2-name").value,
    server2Ip: $("dx-s2-ip").value,
    key: $("dx-key").value,
    group: $("dx-group").value,
    authPort: $("dx-auth-port").value,
    acctPort: $("dx-acct-port").value,
    sourceInterface: $("dx-source").value,
    probeUser: $("dx-probe").value,
    coa: $("dx-coa").checked,
    coaKey: $("dx-coa-key").value,
    hostMode: $("dx-host-mode").value,
    txPeriod: $("dx-tx").value,
    criticalVlan: $("dx-critical").value,
    reauth: $("dx-reauth").checked,
    criticalVoice: $("dx-critical-voice").checked,
    skipWords: $("dx-skip").value,
  };
}

const dx = {
  files: [], // { name, path, text, parsed, isSwitch }
  skip: new Set(), // paths un-ticked in the backups list
  records: [], // { file, portsOff: Set(normName), check, settings }
  stale: false, // settings changed since the last check
};

let deps; // { escapeHtml, openConfigModal, downloadZip, reportError, isConfigFile, isSwitchParsed }

const SHORT = [
  ["TwentyFiveGigE", "Twe"], ["HundredGigE", "Hu"], ["FortyGigabitEthernet", "Fo"], ["TenGigabitEthernet", "Te"],
  ["FiveGigabitEthernet", "Fi"], ["TwoGigabitEthernet", "Tw"], ["GigabitEthernet", "Gi"], ["FastEthernet", "Fa"],
];
const shortName = (n) => {
  const hit = SHORT.find(([long]) => n.startsWith(long));
  return hit ? hit[1] + n.slice(hit[0].length) : n;
};
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const baseName = (name) => String(name).replace(/\.[^.]+$/, "");
const dirOf = (path) => path.split("/").slice(1, -1).join("/");

// ------------------------------------------------------------------- folder

async function onFolderPicked(event) {
  const picked = Array.from(event.target.files || []);
  if (!picked.length) return;
  const root = picked[0].webkitRelativePath.split("/")[0] || "(folder)";
  const files = [];
  for (const f of picked) {
    if (!deps.isConfigFile(f.name)) continue;
    const text = await f.text();
    const parsed = parse(text);
    files.push({ name: f.name, path: f.webkitRelativePath || f.name, text, parsed, isSwitch: deps.isSwitchParsed(parsed) });
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  event.target.value = ""; // so the same folder can be picked again after edits
  dx.files = files;
  dx.skip = new Set(files.filter((f) => !f.isSwitch).map((f) => f.path)); // routers start un-ticked
  dx.records = [];
  $("dx-folder-name").textContent = `${root} · ${plural(files.length, "config file")}`;
  renderFiles();
  renderResults();
  setStatus("");
}

function renderFiles() {
  const e = deps.escapeHtml;
  const box = $("dx-files");
  box.innerHTML = "";
  const all = dx.files;
  const on = all.filter((f) => !dx.skip.has(f.path)).length;
  $("btn-dx-check").disabled = on === 0;
  if (!all.length) return;
  const wrap = document.createElement("div");
  wrap.className = "src-files dx-file-list";
  wrap.innerHTML =
    `<div class="src-files-head"><span class="src-files-title">Backups</span>` +
    `<span class="muted small">${on} of ${all.length} will be processed — un-tick a file to leave it out (no output file is created for it).</span>` +
    (all.length > 1
      ? `<button class="btn btn-ghost src-all" type="button">Tick all</button><button class="btn btn-ghost src-none" type="button">Untick all</button>`
      : "") +
    `</div><div class="merge-files">` +
    all
      .map((f, i) => {
        const checked = !dx.skip.has(f.path);
        const t = f.isSwitch ? "switch" : "router";
        const dir = dirOf(f.path);
        return (
          `<label class="merge-file src-file${checked ? "" : " src-file-off"}"><input type="checkbox" class="src-file-cb" data-i="${i}"${checked ? " checked" : ""} title="Process this file" />` +
          `<span class="merge-file-name">${e(dir ? dir + "/" : "")}${e(f.name)}</span>` +
          `<span class="dev-chip dev-${t}">${t}</span>` +
          `<span class="muted small merge-file-host">${e(f.parsed.hostname || "")}</span></label>`
        );
      })
      .join("") +
    `</div>`;
  wrap.querySelectorAll(".src-file-cb").forEach((cb) =>
    cb.addEventListener("change", () => {
      const f = all[Number(cb.dataset.i)];
      if (cb.checked) dx.skip.delete(f.path);
      else dx.skip.add(f.path);
      renderFiles();
      markStale();
    })
  );
  const bulk = (cls, process) => {
    const btn = wrap.querySelector(cls);
    if (btn)
      btn.addEventListener("click", () => {
        dx.skip = new Set(process ? [] : all.map((f) => f.path));
        renderFiles();
        markStale();
      });
  };
  bulk(".src-all", true);
  bulk(".src-none", false);
  box.appendChild(wrap);
}

// -------------------------------------------------------------------- check

function setStatus(text, bad = false) {
  const el = $("dx-status");
  el.textContent = text;
  el.className = bad ? "v-bad small" : "muted small";
}

/** Results no longer match the settings or the ticked files: ask for a re-run rather than regenerate silently. */
function markStale() {
  if (!dx.records.length || dx.stale) return;
  dx.stale = true;
  $("dx-results").classList.add("dx-stale");
  $("dx-summary").classList.add("dx-stale");
  setStatus("Settings or file ticks changed — press Check again.", true);
  refreshDownload();
}

function refreshDownload() {
  const anyType = $("dx-out-changes").checked || $("dx-out-full").checked;
  const anyOutput = dx.records.some((r) => r.check.supported);
  $("btn-dx-download").disabled = dx.stale || !anyType || !anyOutput;
}

function runCheck(rec) {
  const all = qualifyingPorts(rec.file.parsed, rec.settings).ports.map((p) => p.normName);
  rec.check = checkDot1x(rec.file.parsed, rec.settings, { ports: new Set(all.filter((n) => !rec.portsOff.has(n))) });
}

function onCheck() {
  const settings = readDot1xSettings();
  const problems = validateSettings(settings);
  if (problems.length) {
    setStatus(problems.join(" "), true);
    return;
  }
  dx.records = dx.files
    .filter((f) => !dx.skip.has(f.path))
    .map((file) => {
      const rec = { file, portsOff: new Set(), check: null, settings };
      runCheck(rec);
      return rec;
    });
  dx.stale = false;
  $("dx-results").classList.remove("dx-stale");
  $("dx-summary").classList.remove("dx-stale");
  setStatus("");
  renderResults();
}

const changesName = (rec) => `${baseName(rec.file.name)}_dot1x_changes.txt`;
const fullName = (rec) => `${baseName(rec.file.name)}_dot1x_full.txt`;
const changesOf = (rec) => changesText(rec.check, { hostname: rec.file.parsed.hostname || rec.file.name, settings: rec.settings });
const fullOf = (rec) => applyDot1x(rec.file.text, rec.check).content;

function recState(rec) {
  const c = rec.check;
  if (!c.supported) return { cls: "warn", label: "not a Catalyst 9000" };
  if (c.conflict) return { cls: "bad", label: "other style" };
  if (c.complete) return { cls: "on", label: "✓ complete" };
  return { cls: "warn", label: "needs changes" };
}

function renderResults() {
  const recs = dx.records;
  const root = $("dx-results");
  const open = new Map([...root.children].map((el) => [el.dataset.path, el.open]));
  root.innerHTML = "";
  if (!recs.length) {
    $("dx-summary").innerHTML = "";
    refreshDownload();
    return;
  }
  const complete = recs.filter((r) => r.check.supported && r.check.complete).length;
  const conflict = recs.filter((r) => r.check.conflict).length;
  const unsupported = recs.filter((r) => !r.check.supported).length;
  const needs = recs.length - complete - conflict - unsupported;
  $("dx-summary").innerHTML =
    `<p class="verify-totals"><strong>${recs.length}</strong> checked · ` +
    `<span class="${complete ? "v-good" : "muted"}">${complete} already complete</span> · ` +
    `<span class="${needs ? "v-warn" : "muted"}">${needs} need changes</span> · ` +
    `<span class="${conflict ? "v-bad" : "muted"}">${conflict} in the other style</span>` +
    (unsupported ? ` · <span class="v-warn">${unsupported} not a Catalyst 9000</span>` : "") +
    `</p>`;
  for (const rec of recs) {
    const card = renderCard(rec);
    if (open.get(rec.file.path)) card.open = true;
    root.appendChild(card);
  }
  refreshDownload();
}

const MARK = { present: ["v-ok", "✓"], missing: ["v-bad", "✗"], differs: ["v-warn", "!"], conflict: ["v-bad", "✗"] };
const STATE_TEXT = { present: "present", missing: "missing, will be added", differs: "different, not changed", conflict: "conflict" };

function renderCard(rec) {
  const e = deps.escapeHtml;
  const c = rec.check;
  const card = document.createElement("details");
  card.className = "unit verify-unit dx-unit";
  card.dataset.path = rec.file.path;
  const st = recState(rec);
  const dir = dirOf(rec.file.path);

  let pills = `<span class="feat-pill ${st.cls}">${st.label}</span>`;
  if (c.supported) {
    const gOk = c.counts.globalsPresent === c.counts.globalsTotal;
    const pOk = c.counts.portsDone === c.counts.portsTotal;
    pills +=
      `<span class="feat-pill ${gOk ? "on" : "warn"}">globals ${c.counts.globalsPresent}/${c.counts.globalsTotal}</span>` +
      `<span class="feat-pill ${c.conflict ? "bad" : pOk ? "on" : "warn"}">ports ${c.counts.portsDone}/${c.counts.portsTotal}</span>`;
  }

  let body = "";
  if (c.warnings.length) {
    body += `<ul class="dx-warnings">${c.warnings.map((w) => `<li>${e(w)}</li>`).join("")}</ul>`;
  }
  if (c.supported) {
    body +=
      `<details class="unit-sub" open><summary class="unit-sub-head"><strong>Global config</strong> ` +
      `<span class="muted small">${c.counts.globalsPresent} of ${c.counts.globalsTotal} present` +
      (c.style ? ` · ports already use the ${e(STYLE_LABEL[c.style])} style` : " · no 802.1X on any port yet") +
      `</span></summary><div class="v-checks">` +
      c.items
        .map((i) => {
          const [cls, mark] = MARK[i.state];
          return (
            `<div class="v-check ${cls}"><span class="v-mark">${mark}</span><strong>${e(i.label)}</strong>` +
            `<span>${STATE_TEXT[i.state]}${i.detail ? `: ${e(i.detail)}` : ""}</span></div>`
          );
        })
        .join("") +
      `</div></details>`;

    const allPorts = qualifyingPorts(rec.file.parsed, rec.settings);
    const byName = new Map(c.ports.map((p) => [p.normName, p]));
    const chips = allPorts.ports
      .map((p) => {
        const r = byName.get(p.normName);
        const on = !!r;
        const cls = !on ? "off" : r.state === "done" ? "done" : r.state === "conflict" ? "conflict" : "todo";
        const note = !on
          ? "left out"
          : r.state === "done"
          ? "already configured"
          : r.state === "conflict"
          ? "other style — not changed"
          : `${plural(r.add.length + r.remove.length, "line")} to change`;
        const title = [p.normName, p.description, note, ...(r ? r.differs : [])].filter(Boolean).join("\n");
        return (
          `<label class="dx-port dx-port-${cls}" title="${e(title)}"><input type="checkbox" class="dx-port-cb" data-port="${e(p.normName)}"${on ? " checked" : ""} />` +
          `<span>${e(shortName(p.normName))}</span>${r && r.differs.length ? `<span class="dx-port-flag">!</span>` : ""}</label>`
        );
      })
      .join("");
    const differing = c.ports.filter((p) => p.differs.length);
    body +=
      `<details class="unit-sub" open><summary class="unit-sub-head"><strong>Access ports</strong> ` +
      `<span class="muted small">${c.counts.portsDone} of ${c.counts.portsTotal} configured — un-tick a port to leave it out</span></summary>` +
      `<div class="dx-ports-body">` +
      (allPorts.ports.length
        ? `<div class="dx-port-actions"><button class="btn btn-ghost btn-small dx-ports-all" type="button">Tick all</button>` +
          `<button class="btn btn-ghost btn-small dx-ports-none" type="button">Untick all</button></div><div class="dx-ports">${chips}</div>`
        : `<p class="muted small">No access ports qualify on this switch.</p>`) +
      (allPorts.skipped.length
        ? `<p class="muted small">Skipped by description: ${allPorts.skipped
            .map((p) => `${e(shortName(p.normName))} “${e(p.description || "")}”`)
            .join(", ")}</p>`
        : "") +
      (differing.length
        ? `<ul class="v-list v-note">${differing
            .flatMap((p) => p.differs.map((d) => `<li><code>${e(shortName(p.normName))}</code> ${e(d)} — not changed</li>`))
            .join("")}</ul>`
        : "") +
      `</div></details>`;
  }

  card.innerHTML =
    `<summary class="unit-head"><span class="unit-titlebar">` +
    (dir ? `<span class="unit-site">${e(dir)}</span>` : "") +
    `<span class="unit-host">${e(rec.file.parsed.hostname || "(no hostname)")}</span>` +
    `<span class="muted small">${e(rec.file.name)}${c.version ? ` · IOS ${e(c.version)}` : ""}</span></span>` +
    (c.supported ? `<button class="btn btn-small unit-view" type="button">⤢ view changes</button>` : "") +
    `<span class="feat-pills verify-pills">${pills}</span></summary>` +
    `<div class="unit-body">${body}</div>`;

  const view = card.querySelector(".unit-view");
  if (view)
    view.addEventListener("click", (ev) => {
      ev.preventDefault();
      deps.openConfigModal(rec.file.parsed.hostname || rec.file.name, [
        { name: changesName(rec), text: changesOf(rec) },
        { name: fullName(rec), text: fullOf(rec) },
        { name: rec.file.name, text: rec.file.text },
      ]);
    });

  const retick = (fn) => {
    fn();
    runCheck(rec);
    renderResults();
  };
  card.querySelectorAll(".dx-port-cb").forEach((cb) =>
    cb.addEventListener("change", () =>
      retick(() => {
        if (cb.checked) rec.portsOff.delete(cb.dataset.port);
        else rec.portsOff.add(cb.dataset.port);
      })
    )
  );
  const all = card.querySelector(".dx-ports-all");
  if (all) all.addEventListener("click", () => retick(() => rec.portsOff.clear()));
  const none = card.querySelector(".dx-ports-none");
  if (none)
    none.addEventListener("click", () =>
      retick(() => {
        rec.portsOff = new Set(qualifyingPorts(rec.file.parsed, rec.settings).ports.map((p) => p.normName));
      })
    );
  return card;
}

// ----------------------------------------------------------------- download

function onDownload() {
  const wantChanges = $("dx-out-changes").checked;
  const wantFull = $("dx-out-full").checked;
  const zipFiles = [];
  let switches = 0;
  for (const rec of dx.records) {
    if (!rec.check.supported) continue; // not a Catalyst 9000: report only
    switches++;
    const dir = dirOf(rec.file.path);
    const at = (name) => (dir ? dir + "/" : "") + name;
    if (wantChanges) zipFiles.push({ path: at(changesName(rec)), content: changesOf(rec) });
    if (wantFull) zipFiles.push({ path: at(fullName(rec)), content: fullOf(rec) });
  }
  if (!zipFiles.length) {
    setStatus("Nothing to download — tick an output type and run a check first.", true);
    return;
  }
  deps.downloadZip(buildZip(zipFiles), "crucible-dot1x.zip");
  setStatus(`Downloaded crucible-dot1x.zip · ${plural(zipFiles.length, "file")} for ${switches} switch${switches === 1 ? "" : "es"}.`);
}

// --------------------------------------------------------------------- init

export function initDot1xSection(helpers) {
  deps = helpers;
  $("btn-dx-folder").addEventListener("click", () => $("dx-folder-input").click());
  $("dx-folder-input").addEventListener("change", (e) => onFolderPicked(e).catch(deps.reportError));
  $("btn-dx-check").addEventListener("click", onCheck);
  $("btn-dx-download").addEventListener("click", onDownload);
  $("dx-out-changes").addEventListener("change", refreshDownload);
  $("dx-out-full").addEventListener("change", refreshDownload);
  for (const id of SETTING_IDS) {
    $(id).addEventListener("input", markStale);
    $(id).addEventListener("change", markStale);
  }
  const syncVoice = () => ($("dx-critical-voice").disabled = !$("dx-critical").value.trim());
  $("dx-critical").addEventListener("input", syncVoice);
  syncVoice();
}
