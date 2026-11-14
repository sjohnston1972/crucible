import { test } from "node:test";
import assert from "node:assert/strict";

import { findEncryptedUsernames, encryptedUsernameWarnings } from "../public/lib/template.js";

test("findEncryptedUsernames: flags username lines carrying an already-encrypted password", () => {
  const tpl = [
    "hostname T",
    "username admin privilege 15 secret 9 $9$abc$def",
    "username ops secret 5 $1$abcd$efgh",
    "username legacy password 7 0822455D0A16",
    "username keyed privilege 15 password 6 AAbbCC",
    "username scrypt privilege 15 algorithm-type scrypt secret 8 $8$xyz",
    "end",
  ].join("\r\n");
  assert.deepEqual(findEncryptedUsernames(tpl), [
    { username: "admin", type: 9, keyword: "secret", line: 2 },
    { username: "ops", type: 5, keyword: "secret", line: 3 },
    { username: "legacy", type: 7, keyword: "password", line: 4 },
    { username: "keyed", type: 6, keyword: "password", line: 5 },
    { username: "scrypt", type: 8, keyword: "secret", line: 6 },
  ]);
});

test("findEncryptedUsernames: plain-text passwords and non-username lines are not flagged", () => {
  const tpl = [
    "username admin privilege 15 algorithm-type sha256 secret MyPlainPass1",
    "username ops secret 0 PlainText",
    "username bob password hunter2",
    "username nopass privilege 15",
    "enable secret 9 $9$abc$def",
    "line con 0",
    " password 7 0822455D0A16",
    "! username old secret 9 $9$commented",
    "end",
  ].join("\n");
  assert.deepEqual(findEncryptedUsernames(tpl), []);
  assert.deepEqual(findEncryptedUsernames(""), []);
  assert.deepEqual(findEncryptedUsernames(null), []);
});

test("encryptedUsernameWarnings: one readable warning per flagged user, naming the file and line", () => {
  const w = encryptedUsernameWarnings("hostname T\nusername admin privilege 15 secret 9 $9$abc\n", "base.txt");
  assert.equal(w.length, 1);
  assert.match(w[0], /^base\.txt line 2: username "admin" has a pre-encrypted secret \(type 9\)/);
  assert.doesNotMatch(w[0], /\$9\$abc/); // the hash itself is never echoed
});
