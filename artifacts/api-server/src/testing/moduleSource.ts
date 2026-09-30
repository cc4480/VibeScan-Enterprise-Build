import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * A module's source: the file itself plus the parts split out of it for size
 * (foo.ts, fooBar.ts, foo-baz.ts). Tests that assert on the source text use this so a
 * check can move between the parts without the test caring which one holds it.
 */
export function moduleSource(dir: string, file: string): string {
  const base = file.replace(/\.ts$/, "");
  const parts = readdirSync(dir).filter(
    (f) => f === file || (/^[A-Z-]/.test(f.slice(base.length)) && f.startsWith(base) && f.endsWith(".ts") && !f.endsWith(".test.ts")),
  );
  return parts.map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
}
