import { describe, it, expect } from "vitest";
import { CATEGORY_FAMILY, FAMILIES, categoryHex, categoryFamily } from "./category-colors";

describe("category colours", () => {
  it("gives every family a distinct colour, so two kinds of check are never confused", () => {
    const hexes = Object.values(FAMILIES).map((f) => f.hex);
    expect(new Set(hexes).size).toBe(hexes.length);
    for (const h of hexes) expect(h).toMatch(/^#[0-9a-f]{6}$/i);
  });

  it("puts related categories in one colour", () => {
    expect(categoryHex("Injection")).toBe(categoryHex("Insecure Deserialization"));
    expect(categoryHex("Database Security")).toBe(categoryHex("Cloud Storage Misconfiguration"));
    expect(categoryHex("Injection")).not.toBe(categoryHex("Database Security"));
  });

  it("covers the categories that used to render as plain grey in the report", () => {
    for (const c of ["Broken Access Control", "API Security", "Database Security", "Injection", "Cloud Storage Misconfiguration", "Vulnerable Components", "Mail Transport Security", "Server-Side Request Forgery"]) {
      expect(categoryFamily(c), c).not.toBe("notes");
    }
  });

  it("colours an unknown or missing category neutrally instead of failing", () => {
    expect(categoryHex("Some Future Category")).toBe(FAMILIES.notes.hex);
    expect(categoryHex(null)).toBe(FAMILIES.notes.hex);
    expect(categoryHex(undefined)).toBe(FAMILIES.notes.hex);
  });

  it("only maps to families that exist", () => {
    for (const [category, family] of Object.entries(CATEGORY_FAMILY)) expect(FAMILIES[family], category).toBeDefined();
  });
});
