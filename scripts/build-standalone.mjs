// Builds dist/crucible.html — a single self-contained copy of the GUI that runs
// by double-clicking it (file://), with no server, no install and no network.
//
// Differences from the hosted version:
//   - AI review is removed (it needs the Worker's /api/harden + the API key).
//   - "Load sample data" is removed (it fetches from the server, and the sample
//     configs contain real secrets that should not travel inside this file).
//   - Google Fonts are not loaded; the CSS falls back to system fonts.
//
// Usage: npm run build:standalone

import { build } from "esbuild";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pub = (p) => resolve(root, "public", p);
const outFile = resolve(root, "dist", "crucible.html");

function replaceOnce(text, pattern, replacement, what) {
  if (!pattern.test(text)) throw new Error(`build-standalone: could not find ${what} in index.html`);
  return text.replace(pattern, () => replacement);
}

const bundle = await build({
  entryPoints: [pub("app.js")],
  bundle: true,
  format: "iife",
  target: "es2020",
  minify: false,
  write: false,
  legalComments: "none",
});
// "</script" inside the bundle would end the inline <script> early.
const js = bundle.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");

const css = (await readFile(pub("styles.css"), "utf8")).replace(/<\/style/gi, "<\\/style");

const standaloneCss = `
/* standalone build: features that need the server are hidden */
.ai-btn, .ai-out, #btn-sample { display: none !important; }
`;

let html = await readFile(pub("index.html"), "utf8");

// Drop every external font link (no network on a locked-down laptop).
html = html.replace(/^\s*<link[^>]*fonts\.(googleapis|gstatic)\.com[^>]*>\s*\r?\n/gm, "");

html = replaceOnce(
  html,
  /<link rel="stylesheet" href="\/styles\.css"\s*\/?>/,
  `<style>\n${css}\n${standaloneCss}</style>`,
  "the stylesheet link"
);
html = replaceOnce(
  html,
  /<script type="module" src="\/app\.js"><\/script>/,
  `<script>\n${js}\n</script>`,
  "the app script tag"
);
html = replaceOnce(
  html,
  /local files never leave your browser · AI hardening review is advisory/,
  "standalone edition · runs entirely offline · local files never leave your browser",
  "the footer text"
);

if (/(src|href)="(\/|https?:)/.test(html)) {
  throw new Error("build-standalone: output still references an external file or URL");
}

await mkdir(dirname(outFile), { recursive: true });
await writeFile(outFile, html);
console.log(`Wrote ${outFile} (${(Buffer.byteLength(html) / 1024).toFixed(0)} KB)`);
