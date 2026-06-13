# Crucible — LAN Refresh Configuration Template Tool

A form-driven web tool that migrates Cisco IOS site configs (e.g. router + switch → Layer 3
switch) into target-device templates. It discovers source configs in a chosen folder, extracts
selected interface / routing / VRF / spanning-tree / DHCP data, inserts it into a template,
audits the source against a hardening baseline, and writes the populated template back beside the
source.

See [`spec.md`](./spec.md) for the full specification and the confirmed design decisions (§12).

## Architecture

Hybrid — a Cloudflare Worker serves the static GUI and hosts one backend route; all local file
I/O and config parsing happen **in the browser**.

| Layer | Responsibility |
|---|---|
| **Worker** (`src/index.js`) | Serves `./public` static assets; hosts `POST /api/harden` which calls the Anthropic API (`claude-sonnet-4-6`) for advisory hardening commentary. Holds `ANTHROPIC_API_KEY` as a secret. |
| **Browser** (`public/`) | Folder picking (File System Access API, with a Firefox/Safari upload+zip fallback), Cisco IOS parsing, rule-based hardening, template building, write-back. |

### Client modules (`public/lib/`)
- `parser.js` — indentation-aware Cisco IOS parser (interfaces, routing, VRF, STP, DHCP, hostname).
- `hardening.js` — ~19 deterministic baseline checks → pass/missing/n-a + severity + remediation.
- `template.js` — tag map, block extraction, tag-based / direct insertion, naming + rename, STP root rewriting.
- `redact.js` — strips secrets and builds the structural digest sent to the AI endpoint.
- `zip.js` — dependency-free STORE-method zip writer for the fallback download.

## Develop

```bash
npm install
npm run dev      # wrangler dev — open the printed localhost URL in Chrome/Edge
npm test         # node --test — parser, hardening, template, redaction, zip, end-to-end
```

The folder picker (read/write mode) needs Chromium-based Chrome or Edge. Other browsers fall back
to read-only upload + `.zip` download automatically.

### Local AI review (optional)
Create `.dev.vars` (git-ignored) with `ANTHROPIC_API_KEY=sk-ant-...` to exercise `/api/harden`
locally. Without it the endpoint degrades gracefully and the rule-based audit still runs fully.

## Deploy

```bash
npx wrangler secret put ANTHROPIC_API_KEY   # one-time, holds the key as a Worker secret
npm run deploy
```

## Sample data

- `BourdonSW1.txt` — a real C9300 stack config (root-level site).
- `samples/SiteA/RT1.txt`, `samples/SiteA/SW1.txt` — a router + MST/VRF switch pair for testing
  the merge-into-L3 and STP-root-election flows.
- `public/sample-data/Paisley *.txt` — served to the in-app **Load sample data** button.

## Workflow

1. **Browse** to the master folder → sites (sub-folders with `.txt`/`.cfg`) are listed.
2. Configure **sources/merge**, **collection** (interfaces, routing, VRF, STP, DHCP), **template**,
   **insertion mode**, and **naming**. The **tag map** updates live.
3. **Analyze sites** → per-site results: parsed counts, hardening findings (tick to apply), AI
   review button. Pick the **spanning-tree root** for the scan if STP is collected.
4. **Save outputs** → builds each template (applying ticked hardening + the elected STP root) and
   writes it back beside the source (or into a downloaded `.zip` in fallback mode).

## Source control — read before committing

> ⚠️ **This repository contains real Cisco device configs with live secrets** (SNMP community
> strings, password hashes, TACACS keys) — `BourdonSW1.txt`, `paisley/`, `public/sample-data/`,
> `ReidCore.txt`, `CMB-TUK-SWT02#sh run.txt`, `Aspatria Router.txt`, `Haverford Router.txt`,
> `6509-vss-outputs.txt`. **The repo is therefore PRIVATE — keep it that way.** Do not flip it to
> public without first removing or redacting these files from the full git history (not just the
> working tree).

- **`.env` is git-ignored** (`.gitignore`) and holds `ANTHROPIC_API_KEY` + `CLOUDFLARE_API_TOKEN`.
  Never commit it. The deploy/secret commands read it via `set -a && . ./.env && set +a`.
- Anything you drop into the working directory **gets committed** — new device configs are tracked
  by default. Add throwaway/scratch configs to `.gitignore` if you don't want them in history.
- `node_modules/`, `.dev.vars`, and `.wrangler/` are also ignored.
- The deployed Worker secret (`ANTHROPIC_API_KEY`) lives in Cloudflare, **not** in the repo — set it
  with `npx wrangler secret put ANTHROPIC_API_KEY`, never in a tracked file.

Typical flow:

```bash
git add -A
git status            # confirm no .env / unintended secrets are staged
git commit -m "…"
git push
```
