/* Rule-based Cisco IOS hardening baseline (pure, browser- and Node-importable).
 *
 * Each rule: { id, title, severity, detect(parsed) -> { status, remediation, detail } }
 *   status: 'pass' | 'missing' | 'na'
 *   remediation: array of config lines to inject when the user ticks "Apply"
 *   detail: optional human-readable note (e.g. affected interfaces)
 *
 * This rule set is the source of truth for auto-apply. The AI endpoint may
 * *suggest* additions but never auto-applies. Keep the list in one place so it
 * is easy to extend.
 */

export const SEVERITY = { HIGH: "High", MEDIUM: "Medium", LOW: "Low" };

/** Trimmed, non-empty config lines (includes indented children). */
function linesOf(parsed) {
  return (parsed.lines || []).map((l) => l.trim()).filter((l) => l && l !== "!");
}
const anyLine = (lines, re) => lines.some((l) => re.test(l));

/**
 * True if the device has Layer-2 / spanning-tree characteristics (switchports,
 * STP config, or per-port STP). Switch-only hardening checks are N/A on a pure
 * router so they aren't suggested there.
 */
function looksLikeSwitch(parsed) {
  const ifaces = parsed.interfaces || [];
  if (ifaces.some((f) => (f.switchportLines || []).length > 0)) return true;
  if (ifaces.some((f) => (f.stpLines || []).length > 0)) return true;
  const stp = parsed.spanningTree || {};
  if (stp.mode || (stp.raw && stp.raw.length) || (stp.vlanConfig && stp.vlanConfig.length)) return true;
  return false;
}

export const RULES = [
  {
    id: "service-password-encryption",
    title: "service password-encryption not set",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      return anyLine(lines, /^service password-encryption\b/)
        ? { status: "pass" }
        : { status: "missing", remediation: ["service password-encryption"] };
    },
  },
  {
    id: "enable-secret",
    title: "enable password used instead of enable secret",
    severity: SEVERITY.HIGH,
    detect(_p, lines) {
      if (anyLine(lines, /^enable password\b/))
        return {
          status: "missing",
          remediation: ["enable secret <STRONG-SECRET>", "no enable password"],
          detail: "Replace the weak/reversible enable password with enable secret.",
        };
      return { status: "pass" };
    },
  },
  {
    id: "plaintext-username",
    title: "Plaintext username password (use secret)",
    severity: SEVERITY.HIGH,
    detect(_p, lines) {
      const offenders = lines.filter((l) =>
        /^username\s+\S+\s+(?:privilege\s+\d+\s+)?password\b/.test(l)
      );
      if (offenders.length)
        return {
          status: "missing",
          remediation: offenders.map((l) =>
            l.replace(/\bpassword\b/, "secret").replace(/\s+\S+$/, " <STRONG-SECRET>")
          ),
          detail: `${offenders.length} username(s) use plaintext password.`,
        };
      return { status: "pass" };
    },
  },
  {
    id: "ssh-v2",
    title: "SSH version 2 not enforced",
    severity: SEVERITY.HIGH,
    detect(_p, lines) {
      return anyLine(lines, /^ip ssh version 2\b/)
        ? { status: "pass" }
        : {
            status: "missing",
            remediation: ["ip ssh version 2", "crypto key generate rsa modulus 2048"],
          };
    },
  },
  {
    id: "vty-telnet",
    title: "VTY allows telnet (transport input telnet/all)",
    severity: SEVERITY.HIGH,
    detect(_p, lines) {
      if (anyLine(lines, /^transport input\b.*\b(telnet|all)\b/))
        return {
          status: "missing",
          remediation: ["line vty 0 15", " transport input ssh"],
        };
      return { status: "pass" };
    },
  },
  {
    id: "exec-timeout",
    title: "No exec-timeout on console/VTY",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      return anyLine(lines, /^exec-timeout\b/)
        ? { status: "pass" }
        : {
            status: "missing",
            remediation: ["line con 0", " exec-timeout 5 0", "line vty 0 15", " exec-timeout 5 0"],
          };
    },
  },
  {
    id: "aaa-new-model",
    title: "aaa new-model not enabled",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      return anyLine(lines, /^aaa new-model\b/)
        ? { status: "pass" }
        : { status: "missing", remediation: ["aaa new-model"] };
    },
  },
  {
    id: "ip-http-server",
    title: "ip http server enabled",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      if (anyLine(lines, /^ip http server\b/))
        return { status: "missing", remediation: ["no ip http server"] };
      return { status: "pass" };
    },
  },
  {
    id: "cdp-run",
    title: "CDP enabled globally (untrusted edges)",
    severity: SEVERITY.LOW,
    detect(_p, lines) {
      return anyLine(lines, /^no cdp run\b/)
        ? { status: "pass" }
        : {
            status: "missing",
            remediation: ["no cdp run"],
            detail: "Disable globally, or per-interface 'no cdp enable' on edge ports.",
          };
    },
  },
  {
    id: "login-throttling",
    title: "No login throttling",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      return anyLine(lines, /^login block-for\b/)
        ? { status: "pass" }
        : { status: "missing", remediation: ["login block-for 120 attempts 3 within 60"] };
    },
  },
  {
    id: "snmp-default-community",
    title: "SNMP community public/private",
    severity: SEVERITY.HIGH,
    detect(_p, lines) {
      const bad = lines.filter((l) => /^snmp-server community\s+(public|private)\b/i.test(l));
      if (bad.length)
        return {
          status: "missing",
          remediation: bad.map((l) => "no " + l).concat(["! migrate to SNMPv3 with auth+priv"]),
          detail: "Default community strings present.",
        };
      if (anyLine(lines, /^snmp-server community\b/)) return { status: "pass" };
      return { status: "na" };
    },
  },
  {
    id: "logging",
    title: "No syslog host / buffered logging",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      const hasHost = anyLine(lines, /^logging\s+(host\s+)?\d+\.\d+\.\d+\.\d+/);
      const hasBuffered = anyLine(lines, /^logging buffered\b/);
      if (hasHost && hasBuffered) return { status: "pass" };
      const rem = [];
      if (!hasBuffered) rem.push("logging buffered 16384");
      if (!hasHost) rem.push("logging host <SYSLOG-IP>");
      rem.push("service timestamps log datetime msec");
      return { status: "missing", remediation: rem };
    },
  },
  {
    id: "ntp-auth",
    title: "NTP unauthenticated",
    severity: SEVERITY.LOW,
    detect(_p, lines) {
      if (!anyLine(lines, /^ntp server\b/)) return { status: "na" };
      return anyLine(lines, /^ntp authenticate\b/)
        ? { status: "pass" }
        : {
            status: "missing",
            remediation: [
              "ntp authenticate",
              "ntp authentication-key 1 md5 <KEY>",
              "ntp trusted-key 1",
            ],
          };
    },
  },
  {
    id: "login-banner",
    title: "No login/MOTD legal banner",
    severity: SEVERITY.LOW,
    detect(_p, lines) {
      return anyLine(lines, /^banner (login|motd)\b/)
        ? { status: "pass" }
        : {
            status: "missing",
            remediation: ["banner login ^C Authorised access only. ^C"],
          };
    },
  },
  {
    id: "vty-acl",
    title: "No VTY ACL restricting management",
    severity: SEVERITY.MEDIUM,
    detect(_p, lines) {
      return anyLine(lines, /^access-class\b/)
        ? { status: "pass" }
        : {
            status: "missing",
            remediation: [
              "ip access-list standard MGMT-ACCESS",
              " permit <MGMT-SUBNET> <WILDCARD>",
              "line vty 0 15",
              " access-class MGMT-ACCESS in",
            ],
          };
    },
  },
  {
    id: "service-hardening",
    title: "Legacy services not disabled",
    severity: SEVERITY.LOW,
    detect(_p, lines) {
      const wanted = [
        ["no service pad", /^no service pad\b/],
        ["no ip bootp server", /^no ip bootp server\b/],
        ["no service config", /^no service config\b/],
        ["no ip source-route", /^no ip source-route\b/],
      ];
      const missing = wanted.filter(([, re]) => !anyLine(lines, re)).map(([cmd]) => cmd);
      return missing.length
        ? { status: "missing", remediation: missing, detail: missing.join(", ") }
        : { status: "pass" };
    },
  },
  {
    id: "password-min-length",
    title: "security passwords min-length unset",
    severity: SEVERITY.LOW,
    detect(_p, lines) {
      return anyLine(lines, /^security passwords min-length\b/)
        ? { status: "pass" }
        : { status: "missing", remediation: ["security passwords min-length 10"] };
    },
  },
  {
    id: "bpduguard-default",
    title: "Global BPDU Guard default not set",
    severity: SEVERITY.MEDIUM,
    detect(parsed, lines) {
      if (!looksLikeSwitch(parsed)) return { status: "na", detail: "router — no Layer 2 / spanning-tree" };
      return anyLine(lines, /^spanning-tree portfast bpduguard default\b/)
        ? { status: "pass" }
        : { status: "missing", remediation: ["spanning-tree portfast bpduguard default"] };
    },
  },
  {
    id: "udld-aggressive",
    title: "UDLD aggressive mode not enabled",
    severity: SEVERITY.MEDIUM,
    detect(parsed, lines) {
      if (!looksLikeSwitch(parsed)) return { status: "na", detail: "router — UDLD is for switch fibre uplinks" };
      return anyLine(lines, /^udld aggressive\b/) || anyLine(lines, /^udld enable aggressive\b/)
        ? { status: "pass" }
        : { status: "missing", remediation: ["udld aggressive"] };
    },
  },
  {
    id: "portfast-without-bpduguard",
    title: "PortFast access ports without BPDU Guard",
    severity: SEVERITY.MEDIUM,
    detect(parsed) {
      if (!looksLikeSwitch(parsed)) return { status: "na", detail: "router — no Layer 2 / spanning-tree" };
      const offenders = (parsed.interfaces || []).filter((f) => {
        const hasAccessPortfast = f.stpLines.some(
          (l) => /^spanning-tree portfast$/.test(l) || /^spanning-tree portfast edge$/.test(l)
        );
        const hasBpduGuard = f.stpLines.some((l) => /spanning-tree bpduguard enable/.test(l));
        return hasAccessPortfast && !hasBpduGuard;
      });
      if (!offenders.length) return { status: "pass" };
      const rem = [];
      for (const f of offenders) {
        rem.push(`interface ${f.normName}`, " spanning-tree bpduguard enable");
      }
      return {
        status: "missing",
        remediation: rem,
        detail: `${offenders.length} port(s): ${offenders.map((f) => f.normName).join(", ")}`,
      };
    },
  },
];

/** Run all rules against a parsed config. Returns an array of findings. */
export function audit(parsed) {
  const lines = linesOf(parsed);
  return RULES.map((rule) => {
    let out;
    try {
      out = rule.detect(parsed, lines) || { status: "na" };
    } catch (err) {
      out = { status: "na", detail: `rule error: ${err.message}` };
    }
    return {
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      status: out.status,
      remediation: out.remediation || [],
      detail: out.detail || null,
      apply: false, // user toggles this in the UI for Missing items
    };
  });
}

/** Convenience: the config lines for the findings the user chose to apply. */
export function remediationLines(findings) {
  const out = [];
  for (const f of findings) {
    if (f.apply && f.status === "missing" && f.remediation.length) {
      out.push(`! [${f.severity}] ${f.title}`);
      out.push(...f.remediation);
    }
  }
  return out;
}
