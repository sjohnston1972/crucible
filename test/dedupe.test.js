import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../public/lib/parser.js";
import { removeDuplicateLines } from "../public/lib/template.js";

// ------------------------------------------------ parser: sub-mode logging lines

test("indented logging lines (line con/vty, archive) are not collected as global logging", () => {
  const p = parse(
    [
      "logging host 10.0.0.1",
      "archive",
      " log config",
      "  logging enable",
      "!",
      "line con 0",
      " logging synchronous",
      "line vty 0 4",
      " logging synchronous",
      "line vty 5 15",
      " logging synchronous",
      "!",
      "logging buffered 16384",
      "",
    ].join("\n")
  );
  assert.deepEqual(p.logging, ["logging host 10.0.0.1", "logging buffered 16384"]);
});

// ------------------------------------------------------- removeDuplicateLines

test("removeDuplicateLines: repeated top-level lines collapse to the first one", () => {
  const { content, removed } = removeDuplicateLines(
    "hostname X\nlogging synchronous\nlogging synchronous\nlogging synchronous\nntp server 10.0.0.2\n!\nntp server 10.0.0.2\nend"
  );
  assert.equal(content, "hostname X\nlogging synchronous\nntp server 10.0.0.2\n!\nend");
  assert.deepEqual(removed, ["logging synchronous", "logging synchronous", "ntp server 10.0.0.2"]);
});

test("removeDuplicateLines: a template line repeated by the source data is kept once", () => {
  const { content, removed } = removeDuplicateLines(
    "ip domain name corp.local\n!\n! ==== Management ====\nlogging host 10.0.0.1\n!\ninterface Vlan1\n no ip address\n!\nlogging host 10.0.0.1\nend"
  );
  assert.equal(
    content,
    "ip domain name corp.local\n!\n! ==== Management ====\nlogging host 10.0.0.1\n!\ninterface Vlan1\n no ip address\n!\nend"
  );
  assert.equal(removed.length, 1);
});

test("removeDuplicateLines: separators, blanks and lines inside blocks are never touched", () => {
  const text = [
    "!",
    "!",
    "interface Gi1/0/1",
    " switchport mode access",
    " spanning-tree portfast",
    "!",
    "interface Gi1/0/2",
    " switchport mode access",
    " spanning-tree portfast",
    "!",
    "",
    "",
    "line con 0",
    " logging synchronous",
    "line vty 0 4",
    " logging synchronous",
    "end",
  ].join("\n");
  const { content, removed } = removeDuplicateLines(text);
  assert.equal(content, text);
  assert.deepEqual(removed, []);
});

test("removeDuplicateLines: a repeated block header keeps its own child lines", () => {
  const text = "line con 0\n exec-timeout 5 0\n!\nline con 0\n login authentication default\nend";
  assert.equal(removeDuplicateLines(text).content, text);
});

test("removeDuplicateLines: banner text is left exactly as written", () => {
  const text = [
    "banner motd ^C",
    "**********",
    "Authorised access only",
    "**********",
    "^C",
    "banner login # one line #",
    "logging host 10.0.0.1",
    "logging host 10.0.0.1",
    "end",
  ].join("\n");
  const { content, removed } = removeDuplicateLines(text);
  assert.equal(content, text.replace("logging host 10.0.0.1\nlogging host 10.0.0.1", "logging host 10.0.0.1"));
  assert.deepEqual(removed, ["logging host 10.0.0.1"]);
});

test("removeDuplicateLines: CRLF line endings are kept and still compared", () => {
  const { content, removed } = removeDuplicateLines("ntp server 1.1.1.1\r\nntp server 1.1.1.1\r\nend\r\n");
  assert.equal(content, "ntp server 1.1.1.1\r\nend\r\n");
  assert.equal(removed.length, 1);
});
