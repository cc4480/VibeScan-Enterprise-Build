import { describe, it, expect } from "vitest";
import { cleanAccent, cleanDisplayName, safeAccent, trustView, DISPLAY_NAME_MAX } from "./trustPageView";

const NOW = new Date("2026-10-23T12:00:00.000Z");
const ran = (name: string, findings = 0) => ({ group: "g", name, status: "ran", findings, durationMs: 1 });
const verifiedData = (grade = "B") => ({
  summary: { grade, riskScore: 20 },
  vulnerabilities: [
    { id: "1", name: "Missing CSP", severity: "high", category: "Headers" },
    { id: "2", name: "Server header", severity: "low", category: "Headers" },
    { id: "n", name: "A scan note", severity: "info", category: "Scan Coverage" },
  ],
  tests: [ran("a"), ran("b"), ran("c")],
});
const unverifiedData = () => ({
  ...verifiedData(),
  tests: [ran("a"), { group: "active", name: "injection", status: "skipped", findings: 0, durationMs: 0, reason: "domain not verified: active tests need proof" }],
});

describe("cleanDisplayName", () => {
  it("keeps ordinary names and trims them", () => {
    expect(cleanDisplayName("  Acme Ltd  ")).toBe("Acme Ltd");
    expect(cleanDisplayName("Müller & Söhne GmbH")).toBe("Müller & Söhne GmbH");
  });
  it("makes it one line of plain text", () => {
    expect(cleanDisplayName("Acme\n\n# Heading\tLtd")).toBe("Acme # Heading Ltd");
  });
  it("removes zero-width and bidirectional override characters that could disguise a name", () => {
    expect(cleanDisplayName("Ac​me‮ Ltd")).toBe("Ac me Ltd");
  });
  it("bounds the length", () => {
    expect(cleanDisplayName("x".repeat(500))!.length).toBe(DISPLAY_NAME_MAX);
  });
  it.each([null, undefined, 42, {}, "", "   ", "\n​"])("gives null for %j", (v) => {
    expect(cleanDisplayName(v)).toBeNull();
  });
  it("leaves markup as text, for the page to show as text", () => {
    expect(cleanDisplayName("<script>alert(1)</script>")).toBe("<script>alert(1)</script>");
  });
});

describe("cleanAccent", () => {
  it("accepts #rrggbb in any case, stored lower case", () => {
    expect(cleanAccent("#1A73E8")).toEqual({ ok: true, value: "#1a73e8" });
    expect(cleanAccent(" #00ff00 ")).toEqual({ ok: true, value: "#00ff00" });
  });
  it("treats empty as none", () => {
    for (const v of [undefined, null, ""]) expect(cleanAccent(v)).toEqual({ ok: true, value: null });
  });
  it.each(["red", "#fff", "#12345", "#1234567", "1a73e8", "#gggggg", "url(javascript:alert(1))", "#fff;} body{display:none", 5])("refuses %j", (v) => {
    expect(cleanAccent(v)).toEqual({ ok: false });
  });
});

describe("safeAccent", () => {
  it("uses only a stored value that is a colour", () => {
    expect(safeAccent("#1a73e8")).toBe("#1a73e8");
    for (const v of [null, undefined, "", "#1A73E8", "red", "#fff;}"]) expect(safeAccent(v), String(v)).toBeNull();
  });
});

describe("trustView", () => {
  const view = (over: Partial<Parameters<typeof trustView>[0]> = {}) =>
    trustView({ domain: "shop.example.com", displayName: "Acme", accent: "#1a73e8", data: verifiedData(), scannedAt: new Date("2026-10-20T12:00:00Z"), now: NOW, ...over });

  it("shows the grade, the date, the counts and the coverage, and nothing about individual findings", () => {
    const v = view()!;
    expect(v).toEqual({
      domain: "shop.example.com", displayName: "Acme", accent: "#1a73e8", grade: "B", scannedAt: "2026-10-20T12:00:00.000Z", stale: false,
      findings: { critical: 0, high: 1, medium: 0, low: 1, info: 0, total: 2 },
      coverage: { ran: 3, total: 3 },
    });
    expect(JSON.stringify(v)).not.toContain("Missing CSP");
  });

  it("does not count the scan's own notes as findings", () => {
    expect(view()!.findings!.total).toBe(2);
  });

  it("makes no claim for a scan whose active tests did not run, because its grade covers less than it seems to", () => {
    expect(view({ data: unverifiedData() })).toBeNull();
  });

  it("makes no claim for a report with no test ledger at all", () => {
    expect(view({ data: { summary: { grade: "A" }, vulnerabilities: [] } })).toBeNull();
  });

  it("marks a scan older than 30 days as out of date, and 30 days exactly as current", () => {
    expect(view({ scannedAt: new Date("2026-09-23T12:00:00Z") })!.stale).toBe(false);
    expect(view({ scannedAt: new Date("2026-09-23T11:59:00Z") })!.stale).toBe(true);
    expect(view({ scannedAt: new Date("2026-01-01T00:00:00Z") })!.stale).toBe(true);
  });

  it("never passes on a stored accent that is not a colour", () => {
    expect(view({ accent: "red; } body { display:none" })!.accent).toBeNull();
  });

  it("leaves out a grade the report does not have, rather than inventing one", () => {
    expect(view({ data: { ...verifiedData(), summary: {} } })!.grade).toBeNull();
  });
});
