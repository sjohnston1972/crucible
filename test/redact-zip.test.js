import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { inflateRawSync } from "node:zlib";

import { parse } from "../public/lib/parser.js";
import { redactForAI, maskSecrets, buildSummary } from "../public/lib/redact.js";
import { buildZip } from "../public/lib/zip.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const bourdon = readFileSync(join(__dirname, "..", "public", "sample-data", "bourdon", "BourdonSW1.txt"), "utf8");

// ------------------------------------------------------------------ redaction

test("redactForAI: no known Bourdon secret leaks into the payload", () => {
  const payload = redactForAI(parse(bourdon));
  const json = JSON.stringify(payload);
  const secrets = [
    "$1$.2wj$zfYQCEK8FcQpM.x4FmVkw1",
    "GSAsnmpRead",
    "p1ngS0lar",
    "gsa!write",
    "132B4515085A512E1F361F3E7F7A34",
  ];
  for (const s of secrets) assert.ok(!json.includes(s), `secret leaked: ${s}`);
});

test("buildSummary: structural facts present without secrets", () => {
  const s = buildSummary(parse(bourdon));
  assert.equal(s.hostname, "BourdonSW1");
  assert.equal(s.spanningTree.mode, "pvst");
  assert.ok(s.interfaceCount > 100);
  assert.equal(s.defaultGateway.present, true);
  assert.equal(s.defaultGateway.via, "default-gateway");
});

test("maskSecrets redacts secret/community/key material", () => {
  const masked = maskSecrets(
    "username bob secret 5 $1$abc$def\nsnmp-server community myString RO\n key 7 0123ABCD\n"
  );
  assert.ok(!masked.includes("$1$abc$def"));
  assert.ok(!masked.includes("myString"));
  assert.ok(!masked.includes("0123ABCD"));
  assert.ok(masked.includes("<redacted>"));
});

// ------------------------------------------------------------------ zip

test("buildZip: valid signature and entry count", () => {
  const zip = buildZip([
    { path: "SiteA/router.txt", content: "hostname A\n" },
    { path: "SiteB/switch.txt", content: "hostname B\n" },
  ]);
  // local file header signature PK\x03\x04
  assert.deepEqual([...zip.slice(0, 4)], [0x50, 0x4b, 0x03, 0x04]);
  // end-of-central-directory signature present near the end
  const eocd = zip.slice(zip.length - 22);
  assert.deepEqual([...eocd.slice(0, 4)], [0x50, 0x4b, 0x05, 0x06]);
  // total entries field (offset 10-11 in EOCD) = 2
  assert.equal(eocd[10] | (eocd[11] << 8), 2);
});

test("buildZip: STORE content round-trips (raw inflate of stored bytes)", () => {
  // STORE = method 0, so the stored bytes are the literal content. Verify the
  // first entry's data region equals the original content bytes.
  const content = "hostname RoundTrip\ninterface Vlan1\n";
  const zip = buildZip([{ path: "a.txt", content }]);
  const nameLen = zip[26] | (zip[27] << 8);
  const dataStart = 30 + nameLen;
  const stored = zip.slice(dataStart, dataStart + Buffer.byteLength(content));
  assert.equal(Buffer.from(stored).toString("utf8"), content);
  // sanity: inflateRawSync should NOT be needed for STORE; confirm method byte is 0
  assert.equal(zip[8], 0);
  assert.doesNotThrow(() => inflateRawSync); // import used
});
