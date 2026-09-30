import { describe, it, expect, vi } from "vitest";
import type { Request } from "express";

const seen: unknown[] = [];
vi.mock("./scans", () => ({
  createScanHandler: async (req: Request, res: { status(n: number): unknown; json(b: unknown): unknown }) => {
    seen.push(req.body);
    res.status(201);
    res.json({ scanId: "s1", paidWith: "free" });
  },
  // A limiter that always allows, so only the body handed to the handler is under test.
  scanRateLimit: { decide: () => ({ allowed: true }) },
  scanNetworkRateLimit: { decide: () => ({ allowed: true }) },
}));
vi.mock("@workspace/db", () => ({ db: {}, scansTable: {}, reportsTable: {} }));

import { launchScan } from "./appRouteRunner";

const user = { id: "u1", email: "a@example.test" } as never;
const httpReq = { headers: {}, ip: "203.0.113.5" } as unknown as Request;

describe("launchScan", () => {
  it("passes the GitHub repository to the scan handler when one is given", async () => {
    seen.length = 0;
    const out = await launchScan(httpReq, user, "https://a.example", "https://github.com/acme/shop");
    expect(out.status).toBe(201);
    expect(seen[0]).toEqual({ targetUrl: "https://a.example", githubRepoUrl: "https://github.com/acme/shop" });
  });

  it("sends only the URL when there is no repository", async () => {
    seen.length = 0;
    await launchScan(httpReq, user, "https://a.example");
    expect(seen[0]).toEqual({ targetUrl: "https://a.example" });
  });
});
