import { describe, it, expect } from "vitest";
import { pgTable, text } from "drizzle-orm/pg-core";
import { PgDialect } from "drizzle-orm/pg-core";
import { urlKey, sameSite } from "./urlKey";

describe("urlKey: which stored URLs are the same site", () => {
  it("treats the typed address and the address a scan ended on as one site", () => {
    const same = [
      "https://seclayer.app", "https://seclayer.app/", "https://seclayer.app//", "seclayer.app", "  https://seclayer.app/  ",
      "http://seclayer.app", "HTTPS://WWW.Seclayer.App/", "https://www.seclayer.app/#top",
    ];
    for (const u of same) expect(urlKey(u), u).toBe("seclayer.app");
  });

  it("keeps apart what is not the same site: another host, a lookalike, another path, another query", () => {
    expect(urlKey("https://seclayer.app/")).not.toBe(urlKey("https://seclayer.io/"));
    expect(urlKey("https://seclayer.app/")).not.toBe(urlKey("https://seclayer.app.evil.test/"));
    expect(urlKey("https://seclayer.app/")).not.toBe(urlKey("https://app.seclayer.app/"));
    expect(urlKey("https://seclayer.app/app")).not.toBe(urlKey("https://seclayer.app/admin"));
    expect(urlKey("https://seclayer.app/?a=1")).not.toBe(urlKey("https://seclayer.app/?a=2"));
    expect(urlKey("https://seclayer.app/app/")).toBe(urlKey("https://seclayer.app/app"));
  });
});

describe("sameSite: the SQL form does what urlKey does", () => {
  const t = pgTable("reports", { target: text("target_url") });
  const q = new PgDialect().sqlToQuery(sameSite(t.target, "https://WWW.Seclayer.app/"));

  it("normalises the column the way urlKey normalises the address, and binds the key as a parameter", () => {
    expect(q.params).toEqual(["seclayer.app"]);
    // The same three steps, in the same order: fragment, scheme and www (case-insensitive), trailing slashes; then lower().
    expect(q.sql).toContain(`lower(regexp_replace(regexp_replace(regexp_replace("reports"."target_url", '#.*$', ''), '^https?://(www[.])?', '', 'i'), '/+$', ''))`);
    expect(q.sql).toMatch(/\) = \$1$/);
  });

  it("a Postgres regexp_replace chain and urlKey agree on a battery of inputs (the same patterns, run in JavaScript)", () => {
    const viaSql = (s: string) => s.replace(/#.*$/, "").replace(/^https?:\/\/(www[.])?/i, "").replace(/\/+$/, "").toLowerCase();
    for (const u of ["https://seclayer.app", "https://seclayer.app/", "http://www.seclayer.app/x/", "HTTPS://Seclayer.app/A#f", "https://a.test/?q=1"]) {
      expect(viaSql(u), u).toBe(urlKey(u));
    }
  });
});
