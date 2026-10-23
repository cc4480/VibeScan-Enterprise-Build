import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { ScanVulnerability } from "./scanner";
import { reprobe } from "./reprobe";
import { serve, closeServers } from "./testkit";

// A real server on loopback that reflects a foreign origin in its CORS header and records every method it receives,
// so the test says what the re-probe actually sent rather than what a stub was asked.
let methods: string[] = [];
let target = "";
beforeEach(async () => {
  methods = [];
  const port = await serve((req, res) => {
    methods.push(req.method ?? "");
    res.writeHead(200, { "access-control-allow-origin": "https://other.example", "content-type": "text/html" });
    res.end("");
  });
  target = `http://127.0.0.1:${port}/`;
});
afterEach(closeServers);

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

describe("reprobe active OPTIONS probe", () => {
  it("does not send the OPTIONS request with a crafted Origin when the scan is not verified", async () => {
    await reprobe(target, [corsFinding()], log);
    await reprobe(target, [corsFinding()], log, { allowActiveProbes: false });
    expect(methods).not.toContain("OPTIONS");
    // The passive GET still runs; only the active probe is withheld.
    expect(methods).toContain("GET");
  });

  it("sends the OPTIONS request once the scan is verified", async () => {
    await reprobe(target, [corsFinding()], log, { allowActiveProbes: true });
    expect(methods).toContain("OPTIONS");
  });
});
