import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ScanVulnerability } from "./scanner";

const scanFetch = vi.fn(async (_url: string, _opts: { method?: string }) => ({
  status: 200,
  body: "",
  headers: { "access-control-allow-origin": "https://other.example" } as Record<string, string>,
}));

vi.mock("./http", () => ({ scanFetch: (url: string, opts: { method?: string }) => scanFetch(url, opts) }));
vi.mock("./appOrigin", () => ({ APP_DOMAIN: "secscan.us" }));

import { reprobe } from "./reprobe";

const log = { info: () => {}, warn: () => {} };

// A borderline CORS finding (confidence 50-69) is the only thing that makes the OPTIONS probe run.
const corsFinding = (): ScanVulnerability => ({
  id: "c1",
  name: "CORS Wildcard Origin",
  severity: "medium",
  category: "CORS Misconfiguration",
  description: "",
  evidence: "",
  solution: "",
  confidence: 60,
} as unknown as ScanVulnerability);

const sentMethods = () => scanFetch.mock.calls.map((c) => c[1]?.method);

describe("reprobe active OPTIONS probe", () => {
  beforeEach(() => {
    scanFetch.mockClear();
  });

  it("does not send the OPTIONS request with a crafted Origin when the scan is not verified", async () => {
    await reprobe("https://unverified.example/", [corsFinding()], log);
    await reprobe("https://unverified.example/", [corsFinding()], log, { allowActiveProbes: false });
    expect(sentMethods()).not.toContain("OPTIONS");
    // The passive GET still runs; only the active probe is withheld.
    expect(sentMethods()).toContain("GET");
  });

  it("sends the OPTIONS request once the scan is verified", async () => {
    await reprobe("https://owned.example/", [corsFinding()], log, { allowActiveProbes: true });
    expect(sentMethods()).toContain("OPTIONS");
  });
});
