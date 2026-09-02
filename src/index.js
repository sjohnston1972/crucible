/**
 * Crucible Worker
 *
 * Serves the static GUI (from ./public via the ASSETS binding) and hosts the
 * single backend route /api/harden, which calls the Anthropic API for
 * AI-assisted hardening commentary.
 *
 * The Worker holds ANTHROPIC_API_KEY as a secret so it is never exposed to the
 * browser. All local file I/O and config parsing happen client-side; the client
 * redacts all secrets before posting the structural digest here.
 */

import Anthropic from "@anthropic-ai/sdk";

// Sonnet-class model — the spec's chosen cost/latency default for this endpoint.
const MODEL = "claude-sonnet-4-6";

const SYSTEM_PROMPT = `You are a Cisco IOS network security reviewer assisting a LAN refresh migration.
You receive a REDACTED structural digest of a device config (no secrets, no password hashes,
no SNMP strings, no keys). A deterministic rule-based audit already runs client-side and covers
the common baseline (password encryption, SSH v2, VTY telnet, exec-timeout, AAA, http server,
SNMP default communities, logging, NTP auth, banners, VTY ACL, legacy services, BPDU guard).

FIRST determine the device ROLE from the digest's "role" field (and corroborating signals:
switchports / access+trunk ports / a spanning-tree mode = a switch; routed interfaces with no
switchports = a router). Tailor every finding to that role:
- For a ROUTER, do NOT suggest Layer-2 / switch-only features: DHCP snooping, Dynamic ARP
  Inspection (DAI), storm control, PortFast / BPDU Guard, Root Guard / Loop Guard, port-security,
  or VLAN/STP hardening. Prefer router-relevant items: uRPF, CoPP / control-plane protection,
  routing-protocol authentication (OSPF/EIGRP/BGP), ICMP/ip-options hardening, NTP/AAA, and
  management-plane protection.
- For an L2 or L3 SWITCH, the Layer-2 items above are in scope.

Your job: add CONTEXTUAL findings the rule set may miss — role-appropriate, design-dependent
hardening implied by the structure. Do NOT repeat the baseline checks above unless the digest
shows a clear contradiction.

Every finding is ADVISORY. Output JSON only, matching the provided schema. Keep suggestedConfig
to concrete IOS commands. If nothing noteworthy beyond the baseline, return an empty findings array.`;

const RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          title: { type: "string" },
          severity: { type: "string", enum: ["High", "Medium", "Low"] },
          rationale: { type: "string" },
          suggestedConfig: { type: "string" },
        },
        required: ["title", "severity", "rationale", "suggestedConfig"],
      },
    },
    notes: { type: "string" },
  },
  required: ["findings", "notes"],
};

// Structured output via `output_config.format` (JSON-schema-constrained response) is only
// supported on Claude Fable 5, Fable 5.1, Mythos 5/5.1, Opus 5, Opus 4.8, Sonnet 5, Haiku 4.5,
// and legacy Opus 4.5/4.1 — NOT on claude-sonnet-4-6 (the model used here). Forced tool use is
// supported on every current tool-use-capable model, including claude-sonnet-4-6, so we get a
// schema-shaped result by defining a single tool with `RESPONSE_SCHEMA` as its `input_schema`,
// marking it `strict: true` (schema-valid arguments guaranteed), and forcing `tool_choice` to
// call it. This sidesteps the model/feature mismatch entirely rather than requiring a specific
// model.
const HARDEN_TOOL_NAME = "report_hardening_findings";
const HARDEN_TOOL = {
  name: HARDEN_TOOL_NAME,
  description: "Report the advisory hardening findings for the reviewed Cisco IOS device config.",
  input_schema: RESPONSE_SCHEMA,
  strict: true,
};

// --------------------------------------------------------------------------
// Abuse controls for /api/harden. This is the Worker's only dynamic route —
// every accepted POST bills the project owner's Anthropic account — so the
// checks below run and can reject BEFORE we ever touch the network or
// construct an Anthropic client. Every check fails CLOSED: missing/malformed
// input is rejected, never silently allowed through.
//
// Everything that is NOT /api/harden (index.html, app.js, styles.css,
// /sample-data/**, ...) is served by env.ASSETS.fetch(request) — plain
// static file serving via the Workers Assets binding. That path makes no
// Anthropic calls and costs nothing per-request beyond normal static
// hosting, so it is intentionally left open to anonymous traffic; there is
// nothing there to rate-limit or gate behind an origin check.
// --------------------------------------------------------------------------

// Per-IP fixed-window rate limit.
//
// IMPORTANT — this Worker has no Rate Limiting binding and no KV namespace
// configured in wrangler.toml (no `[[unsafe.bindings]]` of type
// `ratelimit`, no `[[kv_namespaces]]`). Cloudflare's real Rate Limiting
// binding would enforce a limit globally across every edge location; this
// Map instead lives in the memory of a single Worker *isolate*. Cloudflare
// runs many isolates concurrently across edge PoPs (and recycles them), so
// this is a best-effort, PER-ISOLATE approximation, NOT a global limit — an
// attacker whose requests land on different isolates/edges can exceed the
// nominal per-IP rate. It still meaningfully raises the cost/effort of
// hammering a single warm isolate, and degrades gracefully to "allow" only
// within a bounded window per isolate, never silently unbounded. If a Rate
// Limiting binding or KV is added later, swap checkRateLimit() to use it.
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const RATE_LIMIT_MAX_REQUESTS = 10;
const rateLimitBuckets = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  // Opportunistic cleanup so a long-lived isolate doesn't accumulate an
  // unbounded number of per-IP entries under sustained distributed abuse.
  if (rateLimitBuckets.size > 5000) {
    for (const [key, bucket] of rateLimitBuckets) {
      if (now >= bucket.resetAt) rateLimitBuckets.delete(key);
    }
  }
  const bucket = rateLimitBuckets.get(ip);
  if (!bucket || now >= bucket.resetAt) {
    rateLimitBuckets.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (bucket.count >= RATE_LIMIT_MAX_REQUESTS) return false;
  bucket.count += 1;
  return true;
}

/**
 * Origin allowlist. Fails closed: a missing Origin header is treated the
 * same as a disallowed one — real browsers send Origin on same-origin POSTs
 * (not just cross-origin ones), so the app's own front-end always has it;
 * script/curl abuse typically doesn't set it at all.
 *
 * The app's own origin (derived from the incoming request's own URL) is
 * always allowed, so this works unmodified in prod (custom domain), on the
 * *.workers.dev URL, and under `wrangler dev` without hardcoding a hostname.
 * `env.ALLOWED_ORIGIN` (comma-separated) can extend the allowlist for a
 * deployment that fronts the Worker under an additional origin.
 */
function isAllowedOrigin(request, url, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  const allowed = new Set([url.origin]);
  if (env && typeof env.ALLOWED_ORIGIN === "string") {
    for (const o of env.ALLOWED_ORIGIN.split(",")) {
      const trimmed = o.trim();
      if (trimmed) allowed.add(trimmed);
    }
  }
  return allowed.has(origin);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/harden") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405);
      }

      // Origin check and rate limit both run here — before handleHarden
      // ever reads the body or constructs an Anthropic client.
      if (!isAllowedOrigin(request, url, env)) {
        return json({ error: "Forbidden" }, 403);
      }

      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      if (!checkRateLimit(ip)) {
        return json({ error: "Too many requests" }, 429);
      }

      return handleHarden(request, env);
    }

    // Everything else is a static asset (index.html, app.js, styles.css, ...).
    return env.ASSETS.fetch(request);
  },
};

/**
 * POST /api/harden
 * Request:  { hostname, summary }   (summary is a redacted structural digest)
 * Response: { findings: [{ title, severity, rationale, suggestedConfig }], notes }
 */
async function handleHarden(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  if (!body || typeof body.hostname !== "string") {
    return json({ error: "Expected { hostname, summary }" }, 400);
  }

  // Degrade gracefully when the AI is not configured — the rule-based audit
  // is unaffected, so the client still works fully offline.
  if (!env.ANTHROPIC_API_KEY) {
    return json({
      findings: [],
      notes:
        "AI review is not configured on this deployment (ANTHROPIC_API_KEY secret not set). " +
        "The rule-based hardening audit runs entirely client-side and is unaffected.",
    });
  }

  const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });

  try {
    const message = await client.messages.create({
      model: MODEL,
      max_tokens: 2000,
      system: SYSTEM_PROMPT,
      tools: [HARDEN_TOOL],
      tool_choice: { type: "tool", name: HARDEN_TOOL_NAME },
      messages: [
        {
          role: "user",
          content:
            `Device hostname: ${body.hostname}\n\n` +
            `Redacted structural digest (JSON):\n${JSON.stringify(body.summary ?? {}, null, 2)}`,
        },
      ],
    });

    const parsed = parseModelJson(message);
    if (!parsed) {
      console.error("harden: model response had no usable tool_use/parsed_output/text JSON", JSON.stringify(message?.content));
      return json({
        findings: [],
        notes: "AI returned an unparseable response; rule-based audit is unaffected.",
      });
    }
    return json(normalizeResult(parsed));
  } catch (err) {
    // Log the real cause server-side so a broken request shape is visible in Worker logs —
    // the client-facing response below stays a graceful "unavailable" note either way.
    console.error("harden: Anthropic API call failed:", err && err.message ? err.message : err);
    return json({
      findings: [],
      notes: `AI review unavailable (${err && err.message ? err.message : "error"}). Rule-based audit is unaffected.`,
    });
  }
}

/**
 * Extract the findings/notes object from the model response. Tries, in order:
 * 1. The forced tool_use block's `input` (the normal path — already a parsed object).
 * 2. `message.parsed_output`, populated only by the `messages.parse()` helper (not `create()`);
 *    kept as defence in depth in case a future call path uses structured outputs instead.
 * 3. A JSON object extracted from the response text, tolerating stray prose around it.
 */
function parseModelJson(message) {
  const toolUse = (message?.content || []).find((b) => b.type === "tool_use" && b.name === HARDEN_TOOL_NAME);
  if (toolUse && toolUse.input && typeof toolUse.input === "object") return toolUse.input;

  if (message && message.parsed_output) return message.parsed_output;

  const text = (message?.content || [])
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    // Tolerate stray prose around the JSON object.
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try {
      return JSON.parse(m[0]);
    } catch {
      return null;
    }
  }
}

/** Coerce the model output into the strict response contract. */
function normalizeResult(parsed) {
  const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
  return {
    findings: findings
      .filter((f) => f && typeof f.title === "string")
      .map((f) => ({
        title: String(f.title),
        severity: ["High", "Medium", "Low"].includes(f.severity) ? f.severity : "Low",
        rationale: typeof f.rationale === "string" ? f.rationale : "",
        suggestedConfig: typeof f.suggestedConfig === "string" ? f.suggestedConfig : "",
      })),
    notes: typeof parsed.notes === "string" ? parsed.notes : "",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// Exported for unit tests (test/harden.test.js) — both functions are pure and don't need a
// live Worker/API to exercise.
export { parseModelJson, normalizeResult, HARDEN_TOOL_NAME, RESPONSE_SCHEMA };
