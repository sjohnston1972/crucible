# LAN Refresh Configuration Template Tool — Build Specification

**Author:** Steven
**Target builder:** Claude Code
**Status:** Draft v2 — for review
**repo:** https://github.com/sjohnston1972/crucible
---

## 1. Purpose

A form-driven web tool that helps migrate network sites (e.g. router + switch → Layer 3 switch). For each site it:

1. Discovers source configuration files in a chosen folder tree.
2. Extracts selected **interface**, **routing**, **VRF**, **spanning-tree**, and **DHCP** data from Cisco IOS configs.
3. Tags each extracted block (`{a}`, `{b}`, `{c}`, …) and inserts it into a chosen template file — either at matching tag markers in the template, or directly under section headers.
4. Audits the source config against a Cisco IOS hardening baseline, reports what is missing, and optionally injects hardening config into the output template.
5. Saves the populated template back into the **same subfolder** as the source, named from the device hostname (with an optional rename transform).
6. The overall goal is to pull the relevant config from the source device(s) config files and create a configuration template for a target device.
7. Some sites may collapse multiple device configs down into one, e.g a L2 switch and a router may become a L3 switch instead. This may not always be the case.

---

## 2. Architecture (read this first)

A Cloudflare Worker runs on Cloudflare's edge and **cannot read or write the user's local filesystem**. Local file work must happen in the browser. The design is therefore a **hybrid**:

| Layer | Responsibility |
|---|---|
| **Cloudflare Worker** | Serves the static GUI (HTML/JS/CSS). Hosts a single backend endpoint (`/api/harden`) that calls the Anthropic API for AI-assisted hardening commentary. Holds the Anthropic API key as a Worker **secret** (`ANTHROPIC_API_KEY`) so it is never exposed to the browser. |
| **Browser (client)** | All local file I/O via a **read-only folder upload** (`<input type="file" webkitdirectory>`), read, in-memory template build, `.zip` output. All config parsing. All rule-based hardening checks. Renders the form and results. |

### Browser support (implemented — one mode for every browser)
Crucible uses a single, read-only folder-upload mode (`<input type="file" webkitdirectory>`) in
every browser, processes everything in memory, and lets the user **download a `.zip`** containing
the populated templates (a dependency-free client-side zip writer — see `public/lib/zip.js`).
There is deliberately **no** File System Access API (`showDirectoryPicker` / write-back) mode: an
earlier design considered it (see the original draft below and §12.7), but Chrome silently omits
some extensions (e.g. `.cfg`) from its directory enumeration under that API, which would make
discovery unreliable. No in-place write is possible; this is made visible in the UI via the mode
badge and save-bar hint.

<details>
<summary>Original draft (superseded — kept for history; see §12.7)</summary>

- **Primary mode (Chrome / Edge):** File System Access API. User picks the master folder once, grants read/write, tool reads subfolders and writes outputs in place.
- **Fallback mode (Firefox / Safari / unsupported):** Read-only folder upload via `<input type="file" webkitdirectory>`, process in memory, and let the user **download a `.zip`** containing the populated templates (built client-side with JSZip). No in-place write is possible in this mode — make this clearly visible in the UI.

Detect support at load with `'showDirectoryPicker' in window` and switch modes automatically.
</details>

### Tech stack
- Frontend: plain HTML + vanilla JS (or a light framework if Claude Code prefers; keep it a single deployable bundle). Tailwind optional.
- Backend: one Cloudflare Worker (`wrangler`), one route `/api/harden`.
- Libraries: JSZip (fallback zip output). No server-side filesystem libraries — there is no server filesystem.

---

## 3. End-to-end workflow

1. User opens the Worker-hosted page.
2. **Browse** to the master folder → tool recursively finds subfolders containing `.cfg` or `.txt` files. Each qualifying subfolder = one **site**.
3. User configures the collection form (sections 4.2–4.7 below) once; it applies to every site.
4. User browses to / selects the **template file**.
5. User picks **insertion mode** (tag-based or direct) and **output naming** rules.
6. User clicks **Run**. For each site the tool: parses source(s) → extracts tagged data → runs hardening audit → builds the populated template → queues it into the `.zip`, under a path mirroring that subfolder.
7. A per-site results panel shows: hostname found, items extracted, hardening findings, and the output filename written.

---

## 4. GUI specification (form, top to bottom)

### 4.1 Master folder
- **Browse** button → folder upload (`<input type="file" webkitdirectory>`), read-only.
- After selection, list discovered sites (subfolders) and the config files found in each.
- Recurse all levels; a subfolder qualifies if it directly contains ≥1 `.cfg`/`.txt` file.
- **File types:** sources are always plain text — only `.txt` and `.cfg` are discovered and parsed (§12.1). No `.doc`/`.docx` handling.

### 4.2 Source file count & merge
- Numeric input: **number of source files per site** (default 1).
- Checkbox: **Merge sources into one template** (Steven's choice — user-selectable).
  - **Merge on:** all extracted data from every source file in a site combines into **one** output template for that site.
  - **Merge off:** each source file produces its **own** output template.
- **Which file is which:** when count > 1, let the user define a role/slot per source so collection rules can target a specific file. Two mapping methods:
  - **By filename pattern** (e.g. Source A = `*RT*`, Source B = `*SW*`), or
  - **Manual** assignment per site at run time.
- If a site's discovered file count ≠ the expected count, flag the site and let the user proceed or skip.

### 4.3 Interface collection
- One or more **interface name** text inputs (e.g. `GigabitEthernet0/1`, `Vlan10`). Accept short forms (`Gi0/1`, `Te1/0/1`).
- Per interface, a checkbox: **All interface data** vs **IP address only**.
  - *All data* = the full interface block verbatim (everything indented under `interface X` up to the next `!` or next top-level command), description, switchport, ip, etc. **This includes any per-port spanning-tree lines** (`spanning-tree portfast`, `bpduguard`, `guard root`, etc.) — see §4.6.
  - *IP only* = just the `ip address …` line(s) (including secondary).
- **"+ Add interface"** button to add more inputs.
- Each collected interface is assigned the next tag in sequence: first interface → `{a}`, second → `{b}`, etc. (see §5 for the global tag order across all data types).
- If a source has multiple sources (merge), allow the interface row to optionally specify which source slot to pull from.

### 4.4 IP routing
Checkboxes (any combination):
- **Default gateway** — interpreted as the default static route `ip route 0.0.0.0 0.0.0.0 <next-hop>`. If the source is L2-only and uses `ip default-gateway <ip>`, capture that next-hop but **emit the modern default route** in the output (`ip route 0.0.0.0 0.0.0.0 <ip>`) — see §12.2. The target switch supports IP routing, so we migrate to the modern style by default.
- **All static routes** — every `ip route …` line (and `ipv6 route …` if present).
- **Routing protocols** — capture full protocol config blocks: `router ospf <id>` … , `router eigrp <asn>` …, `router bgp <asn>` …, `router rip`, plus related `router-id`, `network`, `neighbor`, `redistribute`, `passive-interface` lines within each block.
- Each selected routing item gets its own tag in sequence.

### 4.5 VRF collection
- Checkbox: **VRFs in use**.
- When ticked: collect, **per VRF**, the VRF definition (`vrf definition <name>` / legacy `ip vrf <name>` with `rd`, `route-target`), the interfaces bound to it (`vrf forwarding <name>` / `ip vrf forwarding <name>`), and the VRF-scoped routing (`address-family … vrf`, `ip route vrf <name> …`, OSPF/BGP per-VRF address-families).
- Output groups extracted data under each VRF name. Each VRF block gets a tag.

### 4.6 Spanning-tree collection (new)
- Checkbox: **Collect spanning-tree configuration**.
- **Important scope note:** spanning-tree config lives in two places. The **per-port** commands (`spanning-tree portfast`, `spanning-tree bpduguard enable`, `spanning-tree guard root`, `spanning-tree link-type`, `cost`, `port-priority`) sit *inside* interface blocks and are already captured when an interface is collected as **All data** (§4.3). This section therefore collects only the **global / per-VLAN / MST** spanning-tree config that lives outside interface blocks, to avoid grabbing the same lines twice.
- When ticked, collect:
  - **Mode:** `spanning-tree mode {pvst | rapid-pvst | mst}` and `spanning-tree extend system-id`.
  - **Global toggles:** `spanning-tree portfast default`, `spanning-tree portfast bpduguard default`, `spanning-tree loopguard default`, `spanning-tree portfast edge default`.
  - **Per-VLAN:** `spanning-tree vlan <list> priority <n>`, `spanning-tree vlan <list> root primary|secondary`, and timers (`hello-time`, `forward-time`, `max-age`).
  - **MST:** the indented `spanning-tree mst configuration` block (`name`, `revision`, `instance <n> vlan <list>`), plus `spanning-tree mst <inst> priority|root …`.
- **Root election (user-chosen, see §12.6):** rather than only flagging conflicts, the tool lets the user pick **which switch in the current scan is the spanning-tree root**. After processing, present the scanned sites/switches and let the user designate the root. The tool then amends the templates so:
  - the **chosen root** carries the correct config to become the **sole root** for the network — e.g. `spanning-tree vlan <list> root primary` (or an explicit low priority such as `priority 4096`) across the relevant VLANs / MST instances;
  - the **non-root** switches are adjusted so they do not contest the root role (no `root primary`; secondary/default or higher priority as appropriate).
- **MST mapping caution:** overlapping or conflicting **MST instance-to-VLAN mappings** across collapsed sources are still surfaced in the results panel for a **manual decision** — do not silently merge those (§12.6).
- The collected spanning-tree block gets a tag in sequence.

### 4.7 DHCP scopes
- Checkbox: **Migrate DHCP scopes**.
- When ticked, collect:
  - All `ip dhcp pool <name>` blocks (network, `default-router`, `dns-server`, `domain-name`, `lease`, `option …`).
  - All `ip dhcp excluded-address <start> <end>` lines.
  - `ip dhcp relay` / `ip helper-address` references on interfaces (note these so the user knows relay vs local scope).
- IOS DHCP syntax is essentially identical on a L3 switch, so migration is largely verbatim copy. Each pool (or the whole DHCP section) gets a tag.

### 4.8 Template file
- **Browse** to select the template file (text). It may contain tag markers (`{a}`, `{b}`, …) at the lines where extracted data should land.

### 4.9 Insertion mode
- Radio: **Tag-based** vs **Direct**.
  - **Tag-based:** the tool replaces each `{x}` marker in the template with the matching extracted block. Markers with no matching data are left blank or removed (configurable; default: remove the line and warn).
  - **Direct:** the template has no markers; the tool appends extracted data under generated section headers (`! ==== Interfaces ====`, `! ==== Spanning tree ====`, `! ==== Static routes ====`, etc.) in a deterministic order.

### 4.10 Hardening audit
- Runs automatically per source during processing.
- **Results panel** lists each baseline check as Pass / Missing / N/A with a short description and severity (High / Medium / Low) — see §7.
- For **Missing** items, a checkbox **"Apply to template"**. Checked items have their remediation config injected into the output (appended under `! ==== Hardening ====`, or at a `{harden}` marker if present).
- Button: **AI review** → sends the parsed config summary to the Worker `/api/harden` endpoint for contextual commentary and any findings the rule set missed. AI output is advisory and clearly labelled as such; it never auto-applies without the user ticking it.
- A global checkbox: **Apply all recommended hardening** for convenience.

### 4.11 Output naming
- Default output name = device **hostname** from the source (`hostname <name>`), with a fixed `.txt` extension (§12.3).
- Checkbox: **Rename hostname** (Steven's choice — user-selectable). When ticked, two methods:
  - **Find / replace** (e.g. find `RT1`, replace `sw1` → `abccorp_RT1` becomes `abccorp_sw1`), or
  - **Suffix swap** (e.g. role token `RT` → `SW`).
- The chosen name is used for **both** the output **filename** and the template's own `hostname` line by default (§12.4). A checkbox can decouple them if needed, but both are the default.
- Output is added to the `.zip` under a path mirroring the source subfolder.
- Collision handling: if the filename already exists, append a numeric suffix and warn.

---

## 5. Tagging model

Tags are assigned globally, in the order the data is defined in the form, so the user knows exactly which marker maps to which block:

1. Interfaces (in the order added) → `{a}`, `{b}`, `{c}`, …
2. Routing items (default gateway, static routes, each protocol) → next letters.
3. VRF blocks → next letters.
4. Spanning-tree block → next letter.
5. DHCP section → next letter.
6. Hardening block → reserved marker `{harden}` (named, not lettered, to avoid drift).

Show the **computed tag map** in the UI before running (e.g. "`{a}` = Gi0/1 (IP only), `{b}` = Gi0/2 (full), `{c}` = static routes, `{d}` = spanning tree …") so the user can lay out the template correctly. Letters beyond `z` continue as `{aa}`, `{ab}`, … .

---

## 6. Cisco IOS parsing rules

Parse line-by-line with indentation awareness. Treat `!` and any non-indented command as a block terminator.

- **Hostname:** first `hostname <name>`.
- **Interface block:** from `interface <name>` until the next line that is not indented (or a `!`). Normalise short/long interface names so `Gi0/1` matches `GigabitEthernet0/1`. Per-port `spanning-tree …` lines are part of this block.
- **IP-only extraction:** the `ip address <ip> <mask>` line(s), including ` secondary`.
- **Static routes:** lines matching `^ip route ` (and `^ipv6 route `).
- **Default route:** `ip route 0.0.0.0 0.0.0.0 …`. Also capture `ip default-gateway` if present, but normalise it to a modern default route on output (§12.2).
- **Routing protocol blocks:** `router <proto> …` until block terminator, preserving all child lines.
- **VRF:** both modern (`vrf definition`) and legacy (`ip vrf`) syntaxes; collect bindings and per-VRF routing/address-families.
- **Spanning tree:**
  - Global single-line commands matching `^spanning-tree ` (mode, extend system-id, portfast default, bpduguard default, loopguard default).
  - Per-VLAN lines `^spanning-tree vlan <list> …` (priority / root / timers).
  - The **indented** `spanning-tree mst configuration` block — treat like an interface block: capture indented children (`name`, `revision`, `instance …`) until the terminator. (This is one of the few global blocks that uses indentation, so don't assume all `spanning-tree` config is single-line.)
- **DHCP:** `ip dhcp pool <name>` blocks, `ip dhcp excluded-address` lines, interface `ip helper-address`.

Edge cases to handle gracefully: configs with CRLF vs LF, leading whitespace variations, banner blocks containing `!`, comment lines, and truncated/partial configs. If a requested interface or item is not found, record it as "not found" per site rather than failing the run.

---

## 7. Hardening baseline (rule-based)

Deterministic checks run client-side. Each has: id, description, severity, detection rule, remediation snippet. Suggested starting set (Cisco IOS):

| Check | Severity | Remediation (example) |
|---|---|---|
| `service password-encryption` absent | Medium | `service password-encryption` |
| `enable password` used instead of `enable secret` | High | `enable secret <…>` (and remove `enable password`) |
| Plaintext `username … password` | High | `username <u> secret <…>` |
| SSH not v2 / no `ip ssh version 2` | High | `ip ssh version 2` + RSA key ≥2048 |
| VTY allows telnet (`transport input telnet`/`all`) | High | `transport input ssh` |
| No `exec-timeout` on console/vty | Medium | `exec-timeout 5 0` |
| `aaa new-model` absent | Medium | `aaa new-model` (+ method lists) |
| `ip http server` enabled | Medium | `no ip http server` / restrict `ip http secure-server` |
| `cdp run` global (untrusted edges) | Low | `no cdp run` or per-interface `no cdp enable` |
| No login throttling | Medium | `login block-for 120 attempts 3 within 60` |
| SNMP community `public`/`private` | High | remove; use SNMPv3 |
| No logging host / buffered | Medium | `logging buffered`, `logging host <ip>`, `service timestamps log datetime msec` |
| No NTP / unauthenticated NTP | Low | `ntp authenticate` + keys |
| No login/MOTD legal banner | Low | `banner login ^C … ^C` |
| No VTY ACL restricting mgmt | Medium | `access-class <acl> in` on `line vty` |
| `no service pad`, `no ip source-route`, `no ip bootp server`, `no service config` absent | Low | apply the `no …` forms |
| `security passwords min-length` unset | Low | `security passwords min-length 10` |
| Global BPDU Guard default not set | Medium | `spanning-tree portfast bpduguard default` |
| PortFast access ports without BPDU Guard | Medium | per-port `spanning-tree bpduguard enable` (detect interfaces with `spanning-tree portfast` but no bpduguard) |

Keep this list in a single data structure so it is easy to extend. The AI endpoint can suggest additions (e.g. context-specific Root Guard / Loop Guard placement, which is design-dependent and not safe to auto-apply) but the rule set is the source of truth for auto-apply.

### Worker `/api/harden` contract
- **Request (POST, JSON):** `{ hostname, summary }` where `summary` is a redacted structural digest of the config (no secrets/keys). Strip password hashes, SNMP strings, and PSKs client-side before sending.
- **Response (JSON):** `{ findings: [{ title, severity, rationale, suggestedConfig }], notes }`.
- Worker calls the Anthropic Messages API server-side using `ANTHROPIC_API_KEY` (set via `wrangler secret put`). Use a current Claude model — confirm the latest model string from docs.claude.com before building; a Sonnet-class model is a good cost/latency default. Instruct the model to return **JSON only**, and parse defensively.

---

## 8. Output / save logic

1. Build the populated template string (tag-based or direct).
2. Apply ticked hardening snippets.
3. Optionally rewrite the `hostname` line.
4. Determine filename from hostname (+ rename transform) and extension.
5. Add the file to the `.zip` under a path mirroring the source subfolder.
6. Record result in the per-site panel.

---

## 9. State / data model (client)

```
Site {
  name,
  sourceFiles: [{ name, role, text, parsed }],
  parsed: { hostname, interfaces[], staticRoutes[], defaultGateway,
            protocols[], vrfs[], spanningTree, dhcpPools[], excludedAddresses[] },
  hardening: [{ id, status, severity, remediation, apply: bool }],
  output: { filename, content, zipped: bool }
}
spanningTree {
  mode,                      // pvst | rapid-pvst | mst
  globalOptions[],           // extend system-id, portfast default, bpduguard default, loopguard default
  vlanConfig[],              // { vlans, priority, root, helloTime, forwardTime, maxAge }
  mstConfig                  // { name, revision, instances[: { id, vlans }], priorities[] }
}
CollectionConfig {
  sourceCount, merge: bool, sourceRoles[],
  interfaces: [{ name, mode: 'full'|'ip', sourceSlot }],
  routing: { defaultGateway, allStatic, protocols },
  vrf: { enabled },
  stp: { enabled, rootSiteName },   // rootSiteName = user-elected spanning-tree root for the scan (§4.6)
  dhcp: { enabled },
  template: { handle, text },
  insertion: 'tag'|'direct',
  naming: { rename: bool, method, find, replace, updateHostnameInConfig, extension }
}
```

---

## 10. Error handling & edge cases
- Missing requested interface/route/VRF/STP/DHCP → log per site, do not abort.
- Site file count mismatch → flag and allow skip/proceed.
- STP root: user elects the root switch for the scan; tool amends templates so the chosen switch is the sole root and others stand down (§4.6, §12.6). Conflicting/overlapping MST instance-to-VLAN mappings across merged sources → flag for manual decision, do not auto-merge.
- Tag in template with no data → remove line + warn (default).
- Per-file build failure → record a warning for that unit and continue with the rest of the run (§12.7 — there is no filesystem permission model to re-prompt, since output is a `.zip` download, not an in-place write).
- Worker/AI failure → degrade gracefully; rule-based audit still works offline.
- Never transmit secrets/hashes to the Worker.

---

## 11. Build phases (suggested for Claude Code)

1. **Scaffold:** Worker + static page; folder picker + subfolder discovery; list sites and files (Chrome path first).
2. **Parser:** Cisco IOS interface/routing/VRF/spanning-tree/DHCP/hostname extraction with unit tests on sample configs.
3. **Form + tag map:** all collection sections, live tag-map preview.
4. **Template engine:** tag-based and direct insertion; output naming + rename.
5. **Write-back:** `.zip` output (see §12.7 — in-place write-back was considered and dropped).
6. **Hardening:** rule-based checks + results UI + apply-to-template.
7. **AI endpoint:** Worker `/api/harden`, redaction, JSON parsing, UI wiring.
8. **Polish:** mismatch handling, warnings, per-site results, fallback-mode messaging.

Recommend a few realistic sample configs (a router, a switch with spanning-tree/MST, a VRF/DHCP example) committed as fixtures so the parser can be tested without real client data.

---

## 12. Resolved decisions (confirmed by Steven)
1. **No binary Word files.** Sources are always plain text with a `.txt` or `.cfg` extension. **Drop** `.doc`/`.docx` handling entirely — no magic-byte detection, no mammoth.js. Discovery looks only for `.txt` and `.cfg`.
2. **Default gateway → modern default route.** Some L2-only devices may use `ip default-gateway <ip>`, but all new switches support basic IP routing, so **migrate to the modern default static route by default**: emit `ip route 0.0.0.0 0.0.0.0 <next-hop>` in the output template even when the source used `ip default-gateway`.
3. **Output extension: `.txt`** (fixed, regardless of template extension).
4. **Rename rewrites both.** When the rename transform is applied, update **both** the output filename **and** the in-config `hostname` line by default.
5. **Cisco IOS only** for now. No NX-OS / IOS-XE handling.
6. **No in-place write-back.** The File System Access API (`showDirectoryPicker` read/write "primary" mode) described earlier in this document was considered but **dropped**: Chrome silently omits some extensions (e.g. `.cfg`) from its directory enumeration under that API, which would make site/file discovery unreliable. Crucible uses a single read-only folder-upload mode (`<input type="file" webkitdirectory>`) in every browser and always delivers output as a downloadable `.zip` (see §2 "Browser support"). Treat every "primary mode" / "write-back" reference elsewhere in this document as historical context, superseded by this decision.
6. **User-elected spanning-tree root.** Rather than only flagging conflicts: let the user choose **which switch in the current scan is the spanning-tree root**. The tool then amends the templates so that the chosen switch has the correct config to become the **sole root** for that network (set its priority/root-primary appropriately) and the non-root switches are adjusted so they do not contest the root role. Overlapping/conflicting MST instance-to-VLAN mappings across sources are still surfaced for manual decision.