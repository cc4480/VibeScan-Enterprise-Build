import { describe, it, expect } from "vitest";
import { LEARN_CHECKS, checkById, categoryOfCheck, checkPageTitle, checkPageDescription, checkManifest, checkPath } from "./learn-checks";

describe("per-check pages", () => {
  it("gives every check an id that is safe in a URL, and no two the same", () => {
    const ids = LEARN_CHECKS.map((c) => c.id);
    for (const id of ids) expect(id, id).toMatch(/^[a-z0-9-]+$/);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("finds a check and its category by id, and nothing for an unknown id", () => {
    expect(checkById("hsts")?.id).toBe("hsts");
    expect(categoryOfCheck("hsts")?.checks.some((c) => c.id === "hsts")).toBe(true);
    expect(checkById("nope")).toBeUndefined();
    expect(checkPath("hsts")).toBe("/learn/hsts");
  });

  it("has a title under 61 characters and a description of 50 to 160, unique per page", () => {
    const titles = new Set<string>();
    const descriptions = new Set<string>();
    for (const c of LEARN_CHECKS) {
      const t = checkPageTitle(c);
      const d = checkPageDescription(c);
      expect(t.length, t).toBeLessThanOrEqual(60);
      expect(d.length, `${c.id}: ${d}`).toBeGreaterThanOrEqual(50);
      expect(d.length, `${c.id}: ${d}`).toBeLessThanOrEqual(160);
      titles.add(t);
      descriptions.add(d);
    }
    expect(titles.size).toBe(LEARN_CHECKS.length);
    expect(descriptions.size).toBe(LEARN_CHECKS.length);
  });

  it("writes a manifest entry for every check", () => {
    const m = checkManifest();
    expect(m.map((e) => e.id)).toEqual(LEARN_CHECKS.map((c) => c.id));
    for (const e of m) expect(e.what && e.fix && e.name).toBeTruthy();
  });
});
