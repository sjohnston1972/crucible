import { test } from "node:test";
import assert from "node:assert/strict";

import worker, { RATE_LIMIT_MAX_REQUESTS } from "../src/index.js";

const ORIGIN = "https://crucible.clydeford.net";

/** A fake env: static assets are a no-op stub, no AI key unless a test opts in. */
function makeEnv(overrides = {}) {
  return {
    ASSETS: { fetch: async () => new Response("static-ok") },
    ...overrides,
  };
}

function harden(body, { origin = ORIGIN, ip = "203.0.113.1" } = {}) {
  const h = new Headers({ "content-type": "application/json" });
  if (origin !== null) h.set("Origin", origin);
  if (ip !== null) h.set("cf-connecting-ip", ip);
  return new Request("https://crucible.clydeford.net/api/harden", {
    method: "POST",
    headers: h,
    body: JSON.stringify(body),
  });
}

// ------------------------------------------------------------ origin allowlist (#8)

test("disallowed Origin -> 403", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden({ hostname: "x", summary: {} }, { origin: "https://evil.example.com", ip: "198.51.100.9" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 403);
});

test("missing Origin -> 403 (fail closed)", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden({ hostname: "x", summary: {} }, { origin: null, ip: "198.51.100.10" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 403);
});

test("allowed Origin (app's own, derived from request URL) passes the origin check", async () => {
  const env = makeEnv({}); // no ANTHROPIC_API_KEY -> graceful degradation, still a 200
  const req = harden({ hostname: "x", summary: {} }, { origin: ORIGIN, ip: "198.51.100.11" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.deepEqual(data.findings, []);
});

// ------------------------------------------------------------ rate limiting (#8)

test("exceeding the per-IP rate limit -> 429, before the limit still 200", async () => {
  const env = makeEnv({}); // graceful-degradation 200s are enough to prove pass-through
  const ip = "198.51.100.42";
  for (let i = 0; i < RATE_LIMIT_MAX_REQUESTS; i++) {
    const res = await worker.fetch(harden({ hostname: "x", summary: {} }, { ip }), env);
    assert.equal(res.status, 200, `request ${i + 1} within the limit should succeed`);
  }
  const res = await worker.fetch(harden({ hostname: "x", summary: {} }, { ip }), env);
  assert.equal(res.status, 429);
  const data = await res.json();
  assert.match(data.error, /too many/i);
});

// ------------------------------------------------------------ static assets untouched

test("non-/api/harden paths still fall through to ASSETS.fetch, no guards applied", async () => {
  const env = makeEnv({});
  const req = new Request("https://crucible.clydeford.net/app.js");
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "static-ok");
});

test("GET /api/harden -> 405, unaffected by origin/rate-limit guards", async () => {
  const env = makeEnv({});
  const req = new Request("https://crucible.clydeford.net/api/harden", { method: "GET" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 405);
});
