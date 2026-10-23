import { describe, it, expect } from "vitest";
import { scanContent } from "./jsScanner";
import { analyzeJwts } from "./jwtAnalysis";
import { extractServiceRoleKey, extractSupabaseConfig } from "./supabase-probes-config";

/**
 * Text that a hostile site can serve must not make a scan wait for minutes.
 *
 * Found while raising the script size limit: the JWT patterns started a scan at every `eyJ` and read to the
 * end of the run of token characters before giving up, so a script that is nothing but `eyJeyJeyJ…` cost the
 * square of its length. Measured before the fix: 40 KB took 1.7 s and 80 KB took 6.7 s per pattern (so 512 KB,
 * the old limit, about 5 minutes, and the 5 MB the scanner now reads about 8 hours), and the same shape in the
 * JWT analysis of the page (30 KB: 0.9 s) and in the service_role search. Every one of these runs on a single
 * thread that also serves other requests. After the fix they are linear: about 15 ms a megabyte.
 *
 * The bound below is generous (a slow machine is ten times slower than this one, and a linear scan has two
 * orders of magnitude to spare) and still far under what the quadratic version needs for the same input.
 */

const MB = 1024 * 1024;
const BOUND_MS = 3000;

const hostile: Record<string, string> = {
  "eyJ repeated": "eyJ".repeat(MB / 3),
  "eyJ with a dot": "eyJ.".repeat(MB / 4),
  "two segments repeated": "eyJabcdefghijkl.eyJabcdefghijkl.".repeat(MB / 32),
  "token characters": "aB3-_".repeat(MB / 5),
};

const time = async (f: () => unknown) => {
  const t0 = performance.now();
  await f();
  return performance.now() - t0;
};

describe.each(Object.entries(hostile))("1 MB of %s", (_name, text) => {
  it("is scanned for secrets in bounded time", async () => {
    expect(await time(() => scanContent(text))).toBeLessThan(BOUND_MS);
  });
  it("is searched for a service_role key in bounded time", async () => {
    expect(await time(() => extractServiceRoleKey(text))).toBeLessThan(BOUND_MS);
  });
  it("is read for a Supabase project in bounded time even when a project URL comes first", async () => {
    expect(await time(() => extractSupabaseConfig(`https://abcdefghijklmnopqrst.supabase.co ${text}`))).toBeLessThan(BOUND_MS);
  });
  it("is analysed for JWTs in bounded time", async () => {
    expect(await time(() => analyzeJwts({}, `<html>${text}</html>`, () => {}))).toBeLessThan(BOUND_MS);
  });
});

describe("the guard does not stop real tokens being found", () => {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const token = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "6f1c2d3e", role: "authenticated" })}.${"s".repeat(43)}`;

  it.each([
    ["after a quote", `x="${token}"`],
    ["after a colon", `{"access_token":"${token}"}`],
    ["after a space", `Authorization: Bearer ${token}`],
    ["after a dot", `a.${token}`],
    ["at the very start", token],
  ])("finds one %s", (_n, text) => {
    expect(scanContent(text).map((h) => h.pattern.name)).toEqual(["Hardcoded JWT Token in Source"]);
  });
});
