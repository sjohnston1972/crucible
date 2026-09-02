import { test } from "node:test";
import assert from "node:assert/strict";

import worker, { handleHarden, RATE_LIMIT_MAX_REQUESTS } from "../src/index.js";

const ORIGIN = "https://crucible.clydeford.net";

/** A fake env: static assets are a no-op stub, no AI key unless a test opts in. */
function makeEnv(overrides = {}) {
  return {
    ASSETS: { fetch: async () => new Response("static-ok") },
    ...overrides,
  };
}

/** Fake Anthropic constructor: records every construction + messages.create call. */
function makeFakeAnthropic(responseBody) {
  const calls = { constructed: 0, created: 0 };
  class FakeAnthropic {
    constructor() {
      calls.constructed += 1;
      this.messages = {
        create: async () => {
          calls.created += 1;
          return responseBody;
        },
      };
    }
  }
  return { FakeAnthropic, calls };
}

function harden(body, { origin = ORIGIN, ip = "203.0.113.1", headers = {}, rawBody } = {}) {
  const text = rawBody !== undefined ? rawBody : JSON.stringify(body);
  const h = new Headers(headers);
  if (origin !== null) h.set("Origin", origin);
  if (ip !== null) h.set("cf-connecting-ip", ip);
  if (!h.has("content-length") && rawBody === undefined) {
    h.set("content-length", String(new TextEncoder().encode(text).length));
  }
  h.set("content-type", "application/json");
  return new Request("https://crucible.clydeford.net/api/harden", {
    method: "POST",
    headers: h,
    body: text,
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

// ------------------------------------------------------------ body size cap (#9)

test("oversized Content-Length -> 413 before the body is even read", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden(
    { hostname: "x", summary: {} },
    { ip: "198.51.100.55", headers: { "content-length": String(64 * 1024) } }
  );
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 413);
});

test("actual oversized body with a missing/understated Content-Length -> 413 (defence in depth)", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const bigSummary = { blob: "x".repeat(64 * 1024) };
  const rawBody = JSON.stringify({ hostname: "x", summary: bigSummary });
  // Deliberately omit content-length so the outer pre-check can't catch it —
  // this exercises handleHarden's own re-check of the bytes it actually read.
  const req = harden(undefined, { ip: "198.51.100.56", rawBody });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 413);
});

// ------------------------------------------------------------ summary validation (#9)

test("non-object summary (array) -> 400", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden({ hostname: "x", summary: [1, 2, 3] }, { ip: "198.51.100.60" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 400);
});

test("non-object summary (string) -> 400", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden({ hostname: "x", summary: "not an object" }, { ip: "198.51.100.61" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 400);
});

test("missing hostname -> 400", async () => {
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden({ summary: {} }, { ip: "198.51.100.62" });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 400);
});

// ------------------------------------------------------------ none of the above reach Anthropic

test("400 (invalid summary) path never constructs or calls the Anthropic client", async () => {
  const { FakeAnthropic, calls } = makeFakeAnthropic({ content: [] });
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });

  // handleHarden is the layer that would construct the client, so inject
  // the fake ctor directly here to prove it's never touched.
  const badSummary = harden({ hostname: "x", summary: "nope" }, { ip: "198.51.100.70" });
  const res = await handleHarden(badSummary, env, { AnthropicCtor: FakeAnthropic });
  assert.equal(res.status, 400);
  assert.equal(calls.constructed, 0);
  assert.equal(calls.created, 0);
});

// ------------------------------------------------------------ legitimate request still succeeds

test("legitimate in-limit request from the app origin reaches the Anthropic call exactly once", async () => {
  const { FakeAnthropic, calls } = makeFakeAnthropic({
    content: [{ type: "text", text: JSON.stringify({ findings: [], notes: "ok" }) }],
  });
  const env = makeEnv({ ANTHROPIC_API_KEY: "test-key" });
  const req = harden({ hostname: "RT1", summary: { role: "router" } }, { ip: "198.51.100.80" });
  const res = await handleHarden(req, env, { AnthropicCtor: FakeAnthropic });
  assert.equal(res.status, 200);
  assert.equal(calls.constructed, 1);
  assert.equal(calls.created, 1);
  const data = await res.json();
  assert.deepEqual(data.findings, []);
  assert.equal(data.notes, "ok");
});
