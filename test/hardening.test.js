import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { parse } from "../public/lib/parser.js";
import { audit, remediationLines, RULES } from "../public/lib/hardening.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const bourdon = readFileSync(join(__dirname, "..", "public", "sample-data", "bourdon", "BourdonSW1.txt"), "utf8");

const find = (findings, id) => findings.find((f) => f.id === id);

test("Bourdon audit: known pass/missing statuses", () => {
  const findings = audit(parse(bourdon));

  // present in Bourdon → pass
  assert.equal(find(findings, "service-password-encryption").status, "pass");
  assert.equal(find(findings, "ssh-v2").status, "pass");
  assert.equal(find(findings, "vty-telnet").status, "pass"); // transport input ssh
  assert.equal(find(findings, "aaa-new-model").status, "pass");
  assert.equal(find(findings, "plaintext-username").status, "pass"); // uses secret 5

  // Bourdon Gi1/0/16 is a real portfast access port with no bpduguard → missing
  const pf = find(findings, "portfast-without-bpduguard");
  assert.equal(pf.status, "missing");
  assert.ok(pf.detail.includes("GigabitEthernet1/0/16"));

  // absent in Bourdon → missing
  assert.equal(find(findings, "ip-http-server").status, "missing");
  assert.equal(find(findings, "exec-timeout").status, "missing");
  assert.equal(find(findings, "bpduguard-default").status, "missing");
  assert.equal(find(findings, "vty-acl").status, "missing");
  assert.equal(find(findings, "login-throttling").status, "missing");
  assert.equal(find(findings, "ntp-auth").status, "missing"); // ntp server but no authenticate
});

test("every rule produces a status for Bourdon", () => {
  const findings = audit(parse(bourdon));
  assert.equal(findings.length, RULES.length);
  for (const f of findings) assert.ok(["pass", "missing", "na"].includes(f.status));
});

test("plaintext username detected and remediated to secret", () => {
  const findings = audit(parse("username bob password 0 hunter2\n"));
  const f = find(findings, "plaintext-username");
  assert.equal(f.status, "missing");
  assert.ok(f.remediation[0].includes("secret"));
});

test("ip http server missing → remediation 'no ip http server'", () => {
  const f = find(audit(parse("ip http server\n")), "ip-http-server");
  assert.equal(f.status, "missing");
  assert.deepEqual(f.remediation, ["no ip http server"]);
});

test("snmp public community flagged High", () => {
  const f = find(audit(parse("snmp-server community public RO\n")), "snmp-default-community");
  assert.equal(f.status, "missing");
  assert.equal(f.severity, "High");
});

test("portfast without bpduguard flags the offending port", () => {
  const cfg = `interface Gi1/0/9
 switchport mode access
 spanning-tree portfast
!
`;
  const f = find(audit(parse(cfg)), "portfast-without-bpduguard");
  assert.equal(f.status, "missing");
  assert.ok(f.detail.includes("GigabitEthernet1/0/9"));
  assert.ok(f.remediation.includes(" spanning-tree bpduguard enable"));
});

test("remediationLines only includes applied missing findings", () => {
  const findings = audit(parse(bourdon));
  // apply nothing → empty
  assert.equal(remediationLines(findings).length, 0);
  // apply ip-http-server
  find(findings, "ip-http-server").apply = true;
  const out = remediationLines(findings);
  assert.ok(out.includes("no ip http server"));
  assert.ok(out.some((l) => l.startsWith("! [Medium]")));
});
