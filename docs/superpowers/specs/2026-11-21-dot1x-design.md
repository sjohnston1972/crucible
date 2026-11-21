# 802.1X implementation check and config generation — design

Date: 2026-11-21. Status: approved by Steven 2026-11-21.

Throughout, "Steven said" marks what was asked for. "My call" marks a decision
I made to fill a gap; each is open to correction.

## 1. Intent

Steven is rolling 802.1X port authentication out across Cisco switches. He wants
Crucible to do two jobs:

1. **Check and fix existing switches.** Take a batch of switch backups, report
   how much of an 802.1X configuration each one already has, and produce the
   config needed to finish the job.
2. **Bake it into a refresh.** When an older switch (e.g. a 2960) is migrated to
   a Catalyst 9000 target in the main flow, the generated full config should
   already carry the 802.1X configuration.

The settings are typed in once and used for every switch.

## 2. What Steven said

- A new section at the bottom of the app: an 802.1X config implementation check.
- Input boxes for all the variables needed to add 802.1X to a Catalyst 9000.
- The same upload option as the config verification tool, to load a batch of
  backups.
- The same per-file untick option as at the top of the app, to filter which
  backups are processed.
- Generate a config **changes** file, with an option to generate the **full**
  config too.
- Also add 802.1X to the main app, so an older 2960 can be turned into a full
  config after selecting the target switch.
- Both configuration styles (classic per-port commands and the newer
  policy-based style) must be available as a selectable option.

## 3. Goals, non-goals, anti-goals

**Goals**
- One set of 802.1X settings, used by both the bottom section and the main flow.
- A per-switch report that says plainly what is present, what is missing, and
  what conflicts.
- Output that can be pasted into a switch: only valid config lines and `!`
  comments.
- Works in the standalone `dist/crucible.html`, with no server call. Files
  never leave the browser.

**Non-goals (this build)**
- Converting a switch already configured in one style to the other.
- Removing existing 802.1X config.
- Configuring ISE, certificates, or supplicants.
- Trunk, routed, or port-channel ports. Access ports only.
- IPv6 RADIUS servers.
- Checking 802.1X in the existing "Verify outputs" section.

**Anti-goals**
- A changes file that would lock users out when pasted. Monitor mode is the
  default, and the output must never silently switch a port to closed mode.
- Mixing the two styles on one switch. IOS-XE does not support a mix, so a
  switch found in the other style is flagged and gets no port lines.
- Guessing a value. A setting left blank is either omitted (optional settings)
  or blocks generation with a message naming the box (required settings).

## 4. Constraints

- Pure browser JavaScript, ES modules, no new dependencies. Logic lives in
  `public/lib/` and must import cleanly under Node for `node --test`.
- Follow the existing patterns: Verify's folder picker (`readVerifyFolder`), the
  source-file tick list (`renderSourceFiles`), the Global additions
  tick-reveals-fields pattern, and zip download (`lib/zip.js`, `downloadZip`).
- After any change under `public/`, run `npm run build:standalone` and commit
  `dist/crucible.html` in the same commit.
- Sources are plain `.txt` / `.cfg` (existing project decision).
- The RADIUS and CoA keys typed in are written to the output in clear text, the
  same way Secure access handles its config-key. The UI says so beside the box.

## 5. Approaches

1. **A dedicated 802.1X module shared by both places (chosen).** A new pure
   module, `public/lib/dot1x.js`, holds the settings model, the generators for
   both styles, the check, and the merge into an existing config. The bottom
   section and the main flow both call it. Trade-off: one more module, but the
   two entry points cannot drift apart and everything is unit-testable.
2. **Extend the hardening rules.** Add 802.1X as rules in `lib/hardening.js` and
   reuse Verify's tick-to-fix flow. Rejected: hardening rules are fixed
   one-line fixes with no inputs; 802.1X needs a dozen settings, two styles and
   multi-line blocks per port.
3. **Two separate implementations**, one in the section and one in the template
   builder. Rejected: the same commands written twice would diverge.

Steven handed over the how; approach 1 is my call.

## 6. The settings (input boxes)

One settings panel, physically inside the new bottom section. Required boxes
are marked; everything else is optional and omitted from the output when blank.

| Setting | Default | Notes |
|---|---|---|
| Style | Policy-based | `Policy-based (IBNS 2.0)` or `Classic (per-port authentication commands)` |
| RADIUS server 1 name | `ISE-1` | required |
| RADIUS server 1 IP | — | required |
| RADIUS server 2 name / IP | `ISE-2` / — | optional second server |
| Shared key | — | required, masked with show toggle, same key for both servers |
| Auth port / accounting port | 1812 / 1813 | |
| Server group name | `ISE-RADIUS` | |
| RADIUS source interface | — | e.g. `Vlan10`; omitted when blank |
| CoA (dynamic authorisation) | on | uses the server IPs as clients |
| CoA key | — | blank = reuse shared key |
| Deployment mode | Monitor | `Monitor` (open, no restriction), `Low impact` (open plus a pre-auth ACL), `Closed` |
| Authentication order | 802.1X then MAB | or `MAB then 802.1X` |
| Host mode | multi-auth | `multi-auth`, `multi-domain`, `multi-host`, `single-host` |
| 802.1X tx-period (seconds) | 10 | |
| Re-authentication | on, timer from server | |
| Critical VLAN (RADIUS unreachable) | — | data VLAN to authorise into; omitted when blank |
| Critical voice | on | only emitted when a critical VLAN is set |
| Server probe username | — | adds `automate-tester`; omitted when blank |
| Skip ports whose description contains | — | comma-separated words, case-insensitive, e.g. `AP, UPLINK, PRINTER` |

The choice of defaults is my call. Monitor mode is the default because it
cannot lock anyone out.

## 7. Which ports get 802.1X

My call, same rule in both places:

- A port qualifies when it is a physical Ethernet port, has
  `switchport mode access` (or has `switchport access vlan` and no
  `switchport mode trunk`), is not a port-channel member, has no IP address,
  and its description does not match the skip words.
- Shut-down access ports qualify (they are usually spare user ports).
- In the bottom section each switch's card lists its qualifying ports with a
  tick each (all ticked), so individual ports can be left out.
- In the main flow there are no per-port ticks: every qualifying port on the
  mapped output gets it, subject to the skip words. This is evaluated after the
  interface map has been applied, so the ports carry their target names.

## 8. What gets generated

`lib/dot1x.js` produces two things from the settings: a **global block** and a
**per-port block**. The reference command sets below are the starting point;
the builder must confirm each against Cisco's current IOS-XE 17.x documentation
(IBNS 2.0 deployment guide and the Catalyst 9000 security configuration guide)
before fixing them in tests, and correct this section if anything differs.

**As built (2026-11-21).** The command sets were checked against Cisco's ISE
Secure Wired Access Prescriptive Deployment Guide and the Catalyst 9300 17.12
security configuration guide, and `public/lib/dot1x.js` is now the reference.
Differences from the sketch below: policy-based style uses
`aaa accounting identity`; `aaa accounting update newinfo periodic 2880` and
`radius-server attribute 31 send nas-port-detail mac-only` are added;
dead-criteria is `time 10 tries 3`; the probe line carries `ignore-acct-port`;
the device-tracking policy has `no protocol udp`; the pre-auth ACL has no tftp
line; the critical voice service-template is defined explicitly. Two things
could not be confirmed from a Cisco page and need a lab test: the MAB-first
control policy (adapted from Cisco's 802.1X-first one) and
`authentication event server alive action reinitialize`. One behaviour differs
from section 9: selecting **Closed** does move ports that are already running
802.1X in open mode to closed, with a warning in the card and the changes file,
because monitor-then-closed is the normal rollout path. The parser was not
changed; `dot1x.js` reads the parsed lines itself.

**Global block, both styles**

```
aaa new-model
!
radius server <name1>
 address ipv4 <ip1> auth-port <auth> acct-port <acct>
 key <key>
 automate-tester username <probe> probe-on        (when probe username set)
radius server <name2> ...                          (when second server set)
!
aaa group server radius <group>
 server name <name1>
 server name <name2>
 ip radius source-interface <iface>               (when set)
!
aaa authentication dot1x default group <group>
aaa authorization network default group <group>
aaa accounting dot1x default start-stop group <group>
!
aaa server radius dynamic-author                   (when CoA on)
 client <ip1> server-key <coa-key>
 client <ip2> server-key <coa-key>
!
radius-server attribute 6 on-for-login-auth
radius-server attribute 8 include-in-access-req
radius-server attribute 25 access-request include
radius-server attribute 31 mac format ietf upper-case
radius-server dead-criteria time 5 tries 3
radius-server deadtime 15
!
dot1x system-auth-control
!
device-tracking policy DOT1X-IPDT
 tracking enable
!
ip access-list extended ACL-PREAUTH                (Low impact mode only)
 permit udp any eq bootpc any eq bootps
 permit udp any any eq domain
 permit udp any any eq tftp
 deny ip any any
```

**Global additions, policy-based style only:** the control class-maps and one
`policy-map type control subscriber DOT1X-MAB-POLICY` implementing the chosen
order, fallback to the second method on failure or no response, and (when a
critical VLAN is set) service-templates that authorise the critical data and
voice VLANs when no RADIUS server answers, and re-initialise when one returns.

**Per-port block, classic style**

```
interface <port>
 authentication host-mode <mode>
 authentication order dot1x mab                    (or mab dot1x)
 authentication priority dot1x mab
 authentication port-control auto
 authentication open                               (Monitor and Low impact)
 authentication periodic
 authentication timer reauthenticate server
 authentication event server dead action authorize vlan <critical>
 authentication event server dead action authorize voice
 authentication event server alive action reinitialize
 mab
 dot1x pae authenticator
 dot1x timeout tx-period <n>
 ip access-group ACL-PREAUTH in                    (Low impact only)
 device-tracking attach-policy DOT1X-IPDT
```

**Per-port block, policy-based style**

```
interface <port>
 access-session host-mode <mode>
 access-session closed                             (Closed mode only)
 access-session port-control auto
 mab
 dot1x pae authenticator
 dot1x timeout tx-period <n>
 ip access-group ACL-PREAUTH in                    (Low impact only)
 device-tracking attach-policy DOT1X-IPDT
 service-policy type control subscriber DOT1X-MAB-POLICY
```

Object names (`DOT1X-IPDT`, `ACL-PREAUTH`, `DOT1X-MAB-POLICY`) are fixed, not
input boxes. My call, to keep the form short.

## 9. The check

`checkDot1x(parsed, settings)` returns a list of items, each with a state:
`present`, `missing`, `differs` (there, but with a different value, e.g. a
RADIUS server at another IP), or `conflict`.

Checked items: `aaa new-model`; each RADIUS server; the server group and its
members; the three AAA method lists; CoA; `dot1x system-auth-control`; device
tracking policy; the pre-auth ACL (Low impact only); the control policy-map
(policy-based only); and per port, whether it carries the port block.

It also detects which style, if any, the switch already uses: classic if any
interface has `authentication port-control`, policy-based if any has
`access-session port-control` or a `service-policy type control subscriber`.

- **No 802.1X at all:** everything is missing; full generation.
- **Same style as selected:** only missing lines are generated. `differs` items
  are reported and **not** overwritten (my call: the tool does not know which
  value is right; the report shows both).
- **Other style than selected:** a `conflict`. Missing global lines common to
  both styles are still generated; port lines and style-specific globals are
  not. The card and the changes file both say why.

**Matching is by what the config does, not by name** (my call). Partly-done
switches will use their own object names, so:

- A RADIUS server is matched by IP address. A server group is matched by
  containing those servers. A method list is matched by pointing at such a
  group. Device tracking and the control policy are matched by a port already
  having one attached.
- Where a matching object exists under another name, generated lines reuse the
  existing name instead of creating a parallel object.
- Port lines are compared one by one, not as a whole block. A port setting that
  takes a single value (host mode, control policy, device-tracking policy,
  order, port-control) and already has a different value is `differs`: reported
  and never emitted, because pasting it would overwrite what is there.
- A port currently in closed mode is never opened: `authentication open` is not
  emitted for it, and for policy-based ports `access-session closed` is never
  removed. Reported as `differs` when the selected mode is Monitor or Low impact.

**`aaa new-model` on a switch that lacks it** (my call): it is still generated,
because nothing else works without it, but the card shows a warning and the
changes file carries a `!` comment directly above the line saying it changes
how administrators log in and to confirm a local user or TACACS login works
before pasting.

**Platform.** Steven said (2026-11-21): the bottom section is only for
Catalyst 9000 series; older models go through the main flow. So there is no
older command set and no recognition of older syntax. As a guard (my call) the
check reads the `version` line: a backup on 15.x or below gets a card saying
"not a Catalyst 9000 — use the main flow at the top" and no output file. A
backup with no `version` line is treated as a Catalyst 9000.

The parser needs extending so the check can see this: the `version` line, RADIUS server blocks,
`aaa group server radius` blocks, the relevant `aaa` lines, and per-interface
authentication lines. Existing parser output must not change shape for existing
callers.

## 10. The new bottom section

Placed after "Verify outputs", in the same card style, titled "802.1X
implementation check" with a step badge.

```
┌ 802.1X implementation check ──────────────────────────────────────────┐
│ [ settings panel — section 6 ]                                         │
│                                                                        │
│ [Browse backups folder…]  site-backups · 14 config files               │
│                                                                        │
│ Backups   12 of 14 will be processed   [Tick all] [Untick all]         │
│  ☑ BLD1-SW1.txt  switch  BLD1-SW1     ☐ BLD1-RT1.txt  router  BLD1-RT1 │
│  ☑ BLD1-SW2.txt  switch  BLD1-SW2     ...                              │
│                                                                        │
│ [Check]   Output: ☑ Changes file  ☐ Full config   [Download .zip]      │
│                                                                        │
│ 12 checked · 3 already complete · 8 need changes · 1 other style       │
│ ▸ BLD1-SW1   needs changes   globals 4/11   ports 0/44                 │
│ ▾ BLD1-SW2   needs changes   globals 11/11  ports 40/46                │
│     ✓ aaa new-model            ✗ CoA client 10.1.1.11                  │
│     ! radius server ISE-1 is 10.9.9.9, settings say 10.1.1.10          │
│     Ports: ☑ Gi1/0/1 ☑ Gi1/0/2 … (skipped: Gi1/0/48 "UPLINK")          │
│     [View changes]                                                     │
└────────────────────────────────────────────────────────────────────────┘
```

- One folder picker. Files are read with the same code as Verify.
- The tick list reuses the look and behaviour of the top source-file list.
  Routers are listed but un-ticked by default (my call); unticked files are not
  checked and get no output.
- "Check" runs the check and renders one collapsible card per switch.
  "View changes" opens the existing config modal with that switch's changes.
- "Download .zip" is disabled until a check has run and at least one output
  type is ticked. Changes file is ticked by default, full config is not.
- Changing a setting after a check marks the results as stale and asks for the
  check to be re-run, rather than regenerating silently.

**Outputs**, in a zip that mirrors the folder structure of the upload:

- `<name>_dot1x_changes.txt` — only the lines that are missing, ready to paste
  in config mode, headed by `!` comments giving the hostname, style, mode, and
  any conflicts or differences. A switch with nothing missing gets a file
  containing only the comment "no changes needed" (my call: a file per switch
  makes it obvious none was forgotten).
- `<name>_dot1x_full.txt` — the original backup with the changes merged in:
  global lines under a `! ==== 802.1X ====` header after the `ip domain name`
  line (via the existing `insertAfterDomainName`), port lines merged into each
  existing interface block. Line endings are preserved, as Verify's
  `applyHardening` does.

## 11. The main flow

- Under "Global additions" a new entry: tick "Add 802.1X to switch outputs",
  with a line saying it uses the settings in the 802.1X section at the bottom
  and a link that scrolls there. No duplicate input boxes.
- When ticked, on Generate, each **switch** output (routers skipped) gets the
  global block and the port block on every qualifying port (section 7). This
  runs after interface mapping and after the template is filled, as a
  post-processing step on the output text, using the same merge function as the
  full-config output in section 10.
- If the tick is on but a required setting is blank, generation stops with a
  message naming the missing box.
- Source configs that already carry 802.1X port lines (my call): the main flow
  builds a new switch from scratch, so the "no conversion" rule for live
  switches does not apply here. Old 802.1X lines on the copied ports
  (`authentication …`, `dot1x …`, `mab`, `access-session …`, control
  `service-policy`) are stripped and the selected style is generated fresh. A
  line in the existing warnings list names each device this was done to. The
  platform rule in section 9 does not apply either: the output is always for
  the Catalyst 9000 target.
- Old global RADIUS/AAA lines are not carried over by the main flow today, so
  there is nothing global to strip.
- The tag map preview is unaffected; 802.1X is not a template marker.

## 12. Testing

- `test/dot1x.test.js`: generators for both styles and all three modes; every
  optional setting on and off; port qualification rules; the check's four
  states; style detection; conflict handling; the merge into an existing
  config (idempotent — merging twice changes nothing); CRLF preservation.
- A parser test for the new 802.1X fields, and confirmation that the existing
  parser tests still pass unchanged.
- An integration test: a 2960-style sample through the main flow with the tick
  on yields a config with the global block and port lines on mapped access
  ports only.
- `npm test` green, then `npm run build:standalone`.

## 13. Left to the builder

- Exact class-map / policy-map / service-template text for the policy-based
  style, confirmed against Cisco documentation.
- Internal function names and how `dot1x.js` is split.
- Card markup and CSS, following the Verify card styles.
- Whether settings persist across reloads (not required).

## 14. Open questions for the customer review

None block the build. Each is listed with what changing it later would cost.

- **Is there an existing standard (a done switch or an ISE team template)?** If
  one turns up, the command sets in section 8 change; the check and UI do not.
- **Fixed object names.** Making them input boxes later is a small change.
- **Per-port ticks in the main flow.** Could be added to the device cards later;
  moderate change.
- **Guest / auth-fail VLANs, and separate keys per server.** Not included; each
  is an extra setting and a few generated lines.
