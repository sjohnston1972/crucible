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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/harden") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405);
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
      output_config: { format: { type: "json_schema", schema: RESPONSE_SCHEMA } },
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
      return json({
        findings: [],
        notes: "AI returned an unparseable response; rule-based audit is unaffected.",
      });
    }
    return json(normalizeResult(parsed));
  } catch (err) {
    // Never fail the request — the client falls back to the rule-based audit.
    return json({
      findings: [],
      notes: `AI review unavailable (${err && err.message ? err.message : "error"}). Rule-based audit is unaffected.`,
    });
  }
}

/** Pull text out of the message content and JSON.parse defensively. */
function parseModelJson(message) {
  if (message && message.parsed_output) return message.parsed_output; // structured-output fast path
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
