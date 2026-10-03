import { describe, it, expect } from "vitest";
import express, { Router, type Request } from "express";
import { formatAccount, formatVerification, formatMonitors } from "./mcp";
import { runAppRoute } from "./appRouteRunner";

/**
 * The tools added in MCP 1.1 do not reimplement anything: each runs the
 * website's own route through runAppRoute. These tests pin that helper — that
 * it runs the route's middleware (auth, rate limits) and honours a refusal —
 * and the text each tool hands the editor.
 */
const user = { id: "u1", email: "owner@example.com" } as any;
const httpReq = { headers: {}, ip: "203.0.113.9", log: { info() {}, warn() {}, error() {} } } as unknown as Request;

describe("runAppRoute", () => {
  it("runs the route's middleware before its handler, as the user, with the given input", async () => {
    const router = Router();
    const seen: string[] = [];
    router.post(
      "/things/:id",
      (req, _res, next) => { seen.push(`mw:${req.user!.id}`); next(); },
      (req, res) => { seen.push(`handler:${req.params.id}:${req.body.x}`); res.status(201).json({ ok: true }); },
    );
    const out = await runAppRoute(router, "post", "/things/:id", httpReq, user, { params: { id: "7" }, body: { x: "y" } });
    expect(seen).toEqual(["mw:u1", "handler:7:y"]);
    expect(out).toEqual({ status: 201, body: { ok: true } });
  });

  it("stops at a middleware that refuses — a rate limit applies to the editor exactly as to the browser", async () => {
    const router = Router();
    let reachedHandler = false;
    router.post(
      "/limited",
      (_req, res) => { res.setHeader("Retry-After", "60"); res.status(429).json({ error: "slow down" }); },
      (_req, res) => { reachedHandler = true; res.json({}); },
    );
    const out = await runAppRoute(router, "post", "/limited", httpReq, user);
    expect(out.status).toBe(429);
    expect(reachedHandler).toBe(false);
  });

  it("fails loudly when the route it expects no longer exists", async () => {
    await expect(runAppRoute(Router(), "get", "/gone", httpReq, user)).rejects.toThrow(/no GET \/gone route/);
  });

  it("works on a real Express request, whose query is a getter-only accessor", async () => {
    // A plain-object request hid this: on the live server Object.assign threw
    // "Cannot set property query … which has only a getter" for every tool.
    const realReq = Object.create(express.request) as Request;
    const router = Router();
    router.get("/q", (req, res) => { res.json({ q: req.query.a, u: req.user!.id }); });
    const out = await runAppRoute(router, "get", "/q", realReq, user, { query: { a: "1" } });
    expect(out.body).toEqual({ q: "1", u: "u1" });
  });

  it("does not leak the caller's input into the real request object", async () => {
    const router = Router();
    router.get("/me", (req, res) => { res.json({ id: req.user!.id, auth: req.isAuthenticated() }); });
    const out = await runAppRoute(router, "get", "/me", httpReq, user);
    expect(out.body).toEqual({ id: "u1", auth: true });
    expect((httpReq as any).user).toBeUndefined();
  });
});

describe("tool output", () => {
  it("get_account: scans left, credits and plan", () => {
    const t = formatAccount({ freeScansRemaining: 16, freeScanLimit: 20, credits: 5, subscription: null, paymentsEnabled: false });
    expect(t).toContain("Free scans left this month: 16 of 20");
    expect(t).toContain("Credits: 5");
    expect(t).toContain("Plan: none");
    expect(t).toContain("Subscribing is not open yet.");
    // Credits are no longer sold, so the line is left out for someone who holds none.
    expect(formatAccount({ freeScansRemaining: 3, freeScanLimit: 3, credits: 0, subscription: null, paymentsEnabled: false })).not.toContain("Credits");
    const pro = formatAccount({
      freeScansRemaining: 0, freeScanLimit: 3, credits: 0, paymentsEnabled: true,
      subscription: { plan: "pro", status: "active", includedScansRemaining: 4, urlLimit: 3, currentPeriodEnd: "2026-10-22T00:00:00.000Z" },
    });
    expect(pro).toContain("Plan: pro (active) · 4 included scans left this period · up to 3 monitored sites · renews 2026-10-22");
    const unlimited = formatAccount({
      freeScansRemaining: 3, freeScanLimit: 3, credits: 0, paymentsEnabled: true,
      subscription: { plan: "unlimited", status: "active", includedScansRemaining: 0, unlimitedScans: true, urlLimit: 5, currentPeriodEnd: "2026-10-22T00:00:00.000Z" },
    });
    // "0 included scans left" would read as out of scans; an unlimited plan has no counter.
    expect(unlimited).toContain("Plan: unlimited (active) · unlimited scans · up to 5 monitored sites · renews 2026-10-22");
    expect(unlimited).not.toContain("included scans left");
  });

  it("start_domain_verification: exactly what to publish, both ways", () => {
    const t = formatVerification({
      domain: "example.com", verified: false, method: null,
      dns: { name: "_secscan-verify.example.com", type: "TXT", value: "tok123" },
      wellKnown: { url: "https://example.com/.well-known/secscan-verify.txt", content: "tok123" },
    });
    expect(t).toContain("not verified yet");
    expect(t).toContain("https://example.com/.well-known/secscan-verify.txt");
    expect(t).toContain("TXT record named _secscan-verify.example.com with the value tok123");
    expect(t).toContain("check_domain_verification");
  });

  it("check_domain_verification: says plainly when it worked", () => {
    const t = formatVerification({ domain: "example.com", verified: true, method: "well_known" });
    expect(t).toBe("Domain: example.com — VERIFIED (file). Its scans now include active tests.");
  });

  it("list_monitors: active monitors only, with grade, uptime and alerts", () => {
    const t = formatMonitors([
      {
        id: "m1", status: "active", targetUrl: "https://example.com",
        lastReport: { id: "r9", grade: "B", riskScore: 20 },
        lastScanAt: "2026-09-23T07:00:00Z", nextScanAt: "2026-09-26T07:00:00Z",
        pulseReachable: true, pulseStatus: 200, responseTimeMs: 143,
        alertCount: 2, regressionCount: 1, certExpiryDays: 40, scanInProgress: false,
      },
      { id: "m2", status: "cancelled", targetUrl: "https://old.example.com" },
    ]);
    expect(t).toContain("https://example.com  (monitor id m1)");
    expect(t).toContain("Grade B · risk 20/100");
    expect(t).toContain("Uptime: up (HTTP 200, 143 ms) · CVE alerts: 2 · new problems in last scan: 1 · certificate expires in 40 days");
    expect(t).toContain("/report/r9");
    expect(t).not.toContain("old.example.com");
  });

  it("list_monitors: says what to do when there are none", () => {
    expect(formatMonitors([])).toMatch(/No sites are being monitored\. Add one with add_monitor/);
  });

  it("list_monitors: a site that is down says so", () => {
    const t = formatMonitors([{ id: "m1", status: "active", targetUrl: "https://x.test", pulseReachable: false, pulseFailureReason: "timeout" }]);
    expect(t).toContain("Uptime: DOWN — timeout");
  });
});
