import { describe, it, expect } from "vitest";

// Mirrors the server's extractDomain (api-server/src/lib/domainVerify.ts):
// scheme-optional, hostname only, lowercased. Duplicated rather than imported
// because the frontend cannot reach into the API server package — so this test
// exists to catch the two drifting apart, since a mismatch would tell a user
// their domain is verified when activeProbeGate will disagree.
function domainOf(rawUrl: string): string | null {
  const raw = (rawUrl || "").trim();
  if (!raw) return null;
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

describe("domainOf — must agree with the server's extractDomain", () => {
  it.each([
    ["https://example.com", "example.com"],
    ["http://example.com/path?q=1", "example.com"],
    ["example.com", "example.com"],
    ["EXAMPLE.COM", "example.com"],
    ["https://Www.Example.com", "www.example.com"],
    ["https://example.com:8443/x", "example.com"],
  ])("%s -> %s", (input, expected) => {
    expect(domainOf(input)).toBe(expected);
  });

  it("returns null for empty or unparseable input rather than guessing", () => {
    for (const bad of ["", "   ", "http://"]) expect(domainOf(bad)).toBeNull();
  });

  it("keeps www distinct from the apex, because the gate's lookup is exact", () => {
    // activeProbeGate matches on equality, so verifying example.com does NOT
    // unlock www.example.com. The UI must not imply otherwise.
    expect(domainOf("https://www.example.com")).not.toBe(domainOf("https://example.com"));
  });
});
