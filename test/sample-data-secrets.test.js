import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

import { maskSecrets } from "../public/lib/redact.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sampleDataDir = join(__dirname, "..", "public", "sample-data");

/**
 * Guard against live device secrets ever being shipped in public/sample-data/
 * again. The Cloudflare Worker serves that directory as world-readable
 * static assets, so anything matching redact.js's SECRET_PATTERNS in there
 * is a live credential exposure the moment the site is deployed.
 *
 * maskSecrets() is a no-op on text that contains no secret-shaped tokens, so
 * asserting maskSecrets(text) === text is both the redaction check and (by
 * construction) proof the sample files are already clean.
 */
function walkTextFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walkTextFiles(p));
    else if (/\.(txt|cfg)$/i.test(entry)) out.push(p);
  }
  return out;
}

/** First 1-based line number where `a` and `b` diverge, for a useful failure message. */
function firstDifferingLine(a, b) {
  const linesA = a.split("\n");
  const linesB = b.split("\n");
  const max = Math.max(linesA.length, linesB.length);
  for (let i = 0; i < max; i++) {
    if (linesA[i] !== linesB[i]) return { line: i + 1, before: linesA[i], after: linesB[i] };
  }
  return null;
}

const files = walkTextFiles(sampleDataDir);

test("public/sample-data/: no file contains a live-secret pattern", () => {
  assert.ok(files.length > 0, "expected at least one sample-data file to scan");

  const offenders = [];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const masked = maskSecrets(text);
    if (masked !== text) {
      const diff = firstDifferingLine(text, masked);
      offenders.push(
        `${relative(sampleDataDir, file)}` +
          (diff ? ` (line ${diff.line}: ${JSON.stringify(diff.before)} -> would redact to ${JSON.stringify(diff.after)})` : "")
      );
    }
  }

  assert.deepEqual(
    offenders,
    [],
    `live secret pattern(s) found in public/sample-data/ — redact before committing:\n${offenders.join("\n")}`
  );
});

test("public/sample-data/: sanity check the guard actually detects secrets", () => {
  // maskSecrets must be non-trivial for at least these known secret shapes,
  // otherwise the "no-op means clean" logic above would pass vacuously.
  const withSecret = "enable secret 5 $1$abc$def\nsnmp-server community RealCommunity RO\n";
  assert.notEqual(maskSecrets(withSecret), withSecret);
});
