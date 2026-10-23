import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { zip } from "./zipWriter";
import { readZip, realUnzipTool, withTempFile } from "./zipReader.testkit";

const WHEN = new Date("2026-10-23T09:30:10.000Z");
const text = (s: string) => Buffer.from(s, "utf8");

describe("zip: read back by an independent reader", () => {
  it("round-trips names and bytes exactly", () => {
    const files = [
      { name: "a.txt", data: text("hello hello hello hello hello hello hello hello") },
      { name: "dir/b.json", data: text(JSON.stringify({ x: 1, list: Array.from({ length: 200 }, (_, i) => i) })) },
      { name: "empty.txt", data: Buffer.alloc(0) },
      { name: "unicode-é-名前.txt", data: text("naïve café 名前") },
    ];
    const out = readZip(zip(files, WHEN));
    expect(out.map((e) => e.name)).toEqual(files.map((f) => f.name));
    out.forEach((e, i) => expect(e.data.equals(files[i]!.data), e.name).toBe(true));
  });

  it("deflates what compresses and stores what does not", () => {
    const random = randomBytes(4_000);
    const out = readZip(zip([{ name: "text.txt", data: text("abc ".repeat(2_000)) }, { name: "random.bin", data: random }], WHEN));
    expect(out.find((e) => e.name === "text.txt")!.method).toBe(8);
    const stored = out.find((e) => e.name === "random.bin")!;
    expect(stored.method).toBe(0);
    expect(stored.data.equals(random)).toBe(true);
  });

  it("holds a large file and many files", () => {
    const big = text("line of text\n".repeat(200_000));
    const many = Array.from({ length: 300 }, (_, i) => ({ name: `f/${i}.txt`, data: text(`file ${i}`) }));
    const out = readZip(zip([{ name: "big.txt", data: big }, ...many], WHEN));
    expect(out).toHaveLength(301);
    expect(out[0]!.data.equals(big)).toBe(true);
    expect(out[300]!.data.toString()).toBe("file 299");
  });
});

describe("zip: reproducible", () => {
  it("gives the same bytes for the same files and date, and different bytes for another date", () => {
    const files = [{ name: "a.txt", data: text("same") }, { name: "b.txt", data: text("files") }];
    expect(zip(files, WHEN).equals(zip(files, WHEN))).toBe(true);
    expect(zip(files, WHEN).equals(zip(files, new Date("2026-10-24T09:30:10.000Z")))).toBe(false);
  });

  it("clamps a date before 1980 to the earliest ZIP can say", () => {
    expect(() => readZip(zip([{ name: "a.txt", data: text("x") }], new Date("1970-01-01T00:00:00Z")))).not.toThrow();
  });
});

describe("zip: refuses a name that could escape the archive", () => {
  it.each(["../evil.txt", "a/../../evil.txt", "/etc/passwd", "a\\b.txt", "", "bad\u0000name.txt", "bad\nname.txt"])("%j", (name) => {
    expect(() => zip([{ name, data: text("x") }], WHEN)).toThrow(/unsafe zip entry name/);
  });
});

describe("zip: opened by a real archiving tool", () => {
  const tool = realUnzipTool();
  const files = [
    { name: "summary.md", data: text("# Summary\n" + "text ".repeat(500)) },
    { name: "nested/data.json", data: text(JSON.stringify({ ok: true })) },
    { name: "unicode-é.txt", data: text("café") },
    { name: "random.bin", data: randomBytes(2_000) },
  ];

  it.skipIf(!tool)("lists every entry", () => {
    const listed = withTempFile(zip(files, WHEN), (file) => tool!.list(file));
    // tar's listing shows directories too; the files must all be there.
    for (const f of files) expect(listed.some((l) => l.replace(/\\/g, "/").endsWith(f.name)), `${tool!.name}: ${f.name}`).toBe(true);
  });

  it.skipIf(!tool)("extracts every file with the exact bytes", () => {
    withTempFile(zip(files, WHEN), (file, dir) => {
      const into = join(dir, "out");
      mkdirSync(into);
      tool!.extract(file, into);
      for (const f of files) expect(readFileSync(join(into, f.name)).equals(f.data), f.name).toBe(true);
    });
  });
});
