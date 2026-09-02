import { test } from "node:test";
import assert from "node:assert/strict";

import { parseModelJson, normalizeResult, HARDEN_TOOL_NAME } from "../src/index.js";

// ------------------------------------------------------------ parseModelJson

test("parseModelJson: reads the forced tool_use block's input (the normal path)", () => {
  const message = {
    content: [
      { type: "text", text: "Reviewing the config..." },
      {
        type: "tool_use",
        id: "toolu_1",
        name: HARDEN_TOOL_NAME,
        input: {
          findings: [{ title: "No uRPF", severity: "Medium", rationale: "…", suggestedConfig: "ip verify unicast source reachable-via rx" }],
          notes: "Router-focused review.",
        },
      },
    ],
  };
  const parsed = parseModelJson(message);
  assert.ok(parsed);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.notes, "Router-focused review.");
});

test("parseModelJson: falls back to parsed_output when present (defence in depth)", () => {
  const message = {
    content: [{ type: "text", text: "no tool call here" }],
    parsed_output: { findings: [], notes: "via parsed_output" },
  };
  const parsed = parseModelJson(message);
  assert.deepEqual(parsed, { findings: [], notes: "via parsed_output" });
});

test("parseModelJson: falls back to extracting JSON from a plain text response", () => {
  const message = {
    content: [{ type: "text", text: 'Sure, here you go:\n{"findings":[],"notes":"text path"}\nHope that helps.' }],
  };
  const parsed = parseModelJson(message);
  assert.deepEqual(parsed, { findings: [], notes: "text path" });
});

test("parseModelJson: returns null for an unusable response", () => {
  assert.equal(parseModelJson({ content: [{ type: "text", text: "no json anywhere" }] }), null);
  assert.equal(parseModelJson({ content: [] }), null);
  assert.equal(parseModelJson(null), null);
});

// ------------------------------------------------------------- normalizeResult

test("normalizeResult: passes through a well-formed findings/notes payload", () => {
  const input = {
    findings: [{ title: "SNMP community default", severity: "High", rationale: "…", suggestedConfig: "no snmp-server community public" }],
    notes: "Looks good otherwise.",
  };
  assert.deepEqual(normalizeResult(input), input);
});

test("normalizeResult: coerces a bad severity to Low and drops findings without a title", () => {
  const result = normalizeResult({
    findings: [
      { title: "Weird severity", severity: "Critical", rationale: "r", suggestedConfig: "c" },
      { severity: "High", rationale: "no title, dropped" },
    ],
    notes: "n",
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, "Low");
});

test("normalizeResult: tolerates a missing/malformed findings array and notes", () => {
  assert.deepEqual(normalizeResult({}), { findings: [], notes: "" });
  assert.deepEqual(normalizeResult({ findings: "not an array", notes: 42 }), { findings: [], notes: "" });
});
