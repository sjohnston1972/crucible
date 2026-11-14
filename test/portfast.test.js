import { test } from "node:test";
import assert from "node:assert/strict";

import { modernisePortfast, removeDuplicateLines } from "../public/lib/template.js";

test("modernisePortfast: per-port and global `portfast edge` lines lose the `edge` keyword", () => {
  const { content, changed } = modernisePortfast(
    [
      "spanning-tree portfast edge default",
      "spanning-tree portfast edge bpduguard default",
      "interface Gi1/0/1",
      " spanning-tree portfast edge",
      "interface Gi1/0/2",
      " spanning-tree portfast edge trunk",
      "interface Gi1/0/3",
      " no spanning-tree portfast edge",
      "end",
    ].join("\n")
  );
  assert.equal(
    content,
    [
      "spanning-tree portfast default",
      "spanning-tree portfast bpduguard default",
      "interface Gi1/0/1",
      " spanning-tree portfast",
      "interface Gi1/0/2",
      " spanning-tree portfast trunk",
      "interface Gi1/0/3",
      " no spanning-tree portfast",
      "end",
    ].join("\n")
  );
  assert.equal(changed, 5);
});

test("modernisePortfast: other spanning-tree lines and CRLF endings are untouched", () => {
  const text =
    "spanning-tree mode rapid-pvst\r\ninterface Gi1/0/1\r\n description portfast edge port\r\n spanning-tree portfast\r\n spanning-tree portfast network\r\n spanning-tree bpduguard enable\r\nend\r\n";
  const { content, changed } = modernisePortfast(text);
  assert.equal(content, text);
  assert.equal(changed, 0);

  assert.equal(modernisePortfast("interface Gi1/0/1\r\n spanning-tree portfast edge\r\n").content, "interface Gi1/0/1\r\n spanning-tree portfast\r\n");
});

test("a converted global line that now repeats a template line is collapsed by the duplicate check", () => {
  const { content } = modernisePortfast("spanning-tree portfast default\n!\nspanning-tree portfast edge default\nend");
  assert.equal(removeDuplicateLines(content).content, "spanning-tree portfast default\n!\nend");
});
