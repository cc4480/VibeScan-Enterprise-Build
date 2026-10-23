import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { servers, serve, closeServers } from "./testkit";

afterEach(closeServers);

// ─── Hardening: reviewer scenarios, each written to fail on the first version ─────────────────

import { runRaceConditionProbeDetailed, isClaimEndpointUrl } from "./raceConditionProbe.js";

type Req = http.IncomingMessage;
type Res = http.ServerResponse;
const CREDS = { cookie: "sid=abc" };
const inScan = <T>(port: number, fn: () => Promise<T>) => runWithScanHttp({ targetUrl: `http://127.0.0.1:${port}/` }, fn);
const drain = (req: Req) => new Promise<void>((r) => { req.on("data", () => {}); req.on("end", () => r()); });

/** A real one-time claim with the classic bug: check, wait, then mark. */
function racyClaim(refusal: (res: Res) => void = (res) => res.writeHead(409, { "content-type": "application/json" }).end(`{"error":"Code already redeemed"}`)) {
  let used = false;
  return async (req: Req, res: Res) => {
    await drain(req);
    if (used) return refusal(res);
    await new Promise((r) => setTimeout(r, 30));
    used = true;
    res.writeHead(200, { "content-type": "application/json" }).end(`{"applied":true}`);
  };
}
/** A correct claim: check and mark in one synchronous step. */
function atomicClaim(refusal: (res: Res) => void = (res) => res.writeHead(409, { "content-type": "application/json" }).end(`{"error":"no longer valid"}`)) {
  let used = false;
  return async (req: Req, res: Res) => {
    await drain(req);
    if (used) return refusal(res);
    used = true;
    res.writeHead(200, { "content-type": "application/json" }).end(`{"applied":true}`);
  };
}

describe("isClaimEndpointUrl: the path decides, and only a claim-shaped last segment counts", () => {
  it.each([
    "https://app.acme.com/api/coupon/redeem",
    "https://app.acme.com/api/promo/claim",
    "https://app.acme.com/api/promo/apply-code",
    "https://app.acme.com/api/redeem",
    "https://app.acme.com/api/redeem_code",
    "https://app.acme.com/api/redeemCoupon",
    "https://app.acme.com/api/applyPromoCode",
    "https://app.acme.com/api/voucher/redeem",
    "https://app.acme.com/api/rewards/claim",
    "https://app.acme.com/api/coupon/apply",
  ])("accepts %s", (url) => {
    expect(isClaimEndpointUrl(url)).toBe(true);
  });

  it.each([
    // The host names are the trap: the regex used to run over the whole URL.
    "https://promo.acme.com/api/account/delete",
    "https://promo.acme.com/api/logout",
    "https://claim.acme.com/api/users/me",
    "https://coupon.acme.com/api/orders",
    // Idempotent lookups and collections, not one-time actions.
    "https://app.acme.com/api/coupon/validate",
    "https://app.acme.com/api/coupons",
    "https://app.acme.com/api/claims",
    "https://app.acme.com/api/promo",
  ])("rejects %s", (url) => {
    expect(isClaimEndpointUrl(url)).toBe(false);
  });
});

describe("runRaceConditionProbe: where it will and will not POST", () => {
  it("never POSTs to a destructive route, however claim-shaped the host or path", async () => {
    const seen: string[] = [];
    const port = await serve(async (req, res) => { seen.push(`${req.method} ${req.url}`); await drain(req); res.writeHead(200).end("{}"); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({
      endpoints: [`http://127.0.0.1:${port}/api/coupon/remove`, `http://127.0.0.1:${port}/api/promo/cancel`, `http://127.0.0.1:${port}/api/claim/delete`],
      credentials: CREDS,
    }));
    expect(seen).toEqual([]);
    expect(out.notTested).toMatch(/no claim-style endpoint/i);
  });

  it("never POSTs to a third-party host that arrived through the target's spec", async () => {
    const thirdParty: string[] = [];
    const tp = http.createServer(async (req, res) => { thirdParty.push(`${req.method} ${req.url}`); await drain(req); res.writeHead(200).end("{}"); });
    servers.push(tp);
    await new Promise<void>((r) => tp.listen(0, "127.0.0.2", r));
    const tpPort = (tp.address() as AddressInfo).port;
    const port = await serve((_req, res) => { res.writeHead(404).end(); });
    await inScan(port, () => runRaceConditionProbeDetailed({
      endpoints: [{ url: `http://127.0.0.2:${tpPort}/api/coupon/redeem`, method: "POST", source: "spec" }],
      credentials: CREDS,
    }));
    expect(thirdParty).toEqual([]);
  });

  it("never POSTs a URL that still holds a placeholder", async () => {
    const seen: string[] = [];
    const port = await serve(async (req, res) => { seen.push(req.url ?? ""); await drain(req); res.writeHead(200).end("{}"); });
    await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupons/{id}/redeem`], credentials: CREDS }));
    expect(seen).toEqual([]);
  });

  it("does not follow a redirect with the POST", async () => {
    const seen: string[] = [];
    const port = await serve(async (req, res) => { seen.push(req.url ?? ""); await drain(req); res.writeHead(307, { Location: "/somewhere-else" }).end(); });
    await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(seen.every((u) => u === "/api/coupon/redeem")).toBe(true);
  });
});

describe("runRaceConditionProbe: findings", () => {
  it("reports a real race, and sends exactly five concurrent requests plus one control", async () => {
    let n = 0;
    const handler = racyClaim();
    const port = await serve(async (req, res) => { n++; await handler(req, res); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.cweId).toBe("CWE-362");
    expect(out.notTested).toBeUndefined();
    expect(n).toBe(6);
  });

  it("reports the race even when the endpoint says 'already been used' in a 200 body to the losers", async () => {
    const port = await serve(racyClaim((res) => res.writeHead(200, { "content-type": "application/json" }).end(`{"error":"Code has already been used"}`)));
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.findings).toHaveLength(1);
  });
});

describe("runRaceConditionProbe: a generic refusal after the burst is not a one-time rule", () => {
  // Five 200s and then a rate limiter's or WAF's JSON 403/429 on the sixth: the sixth says nothing
  // about the action having been used, so this used to be reported as a HIGH race at confidence 90.
  it.each([
    ["a JSON 403 from a WAF", 403, `{"error":"Forbidden"}`],
    ["a JSON 429 rate limit", 429, `{"error":"Too many requests"}`],
    ["a JSON 403 rate limit message", 403, `{"message":"Rate limit exceeded"}`],
    ["a JSON 400 invalid code", 400, `{"error":"Invalid code"}`],
  ])("does not fire when the sixth reply is %s", async (_n, status, body) => {
    let n = 0;
    const port = await serve(async (req, res) => {
      await drain(req);
      n++;
      if (n <= 5) return void res.writeHead(200, { "content-type": "application/json" }).end(`{"data":{"credits":10}}`);
      res.writeHead(status, { "content-type": "application/json" }).end(body);
    });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/rewards/claim`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
  });

  it("never counts a body cut off by the deadline as an accepted reply", async () => {
    // Headers and the start of a JSON document, then silence: the reader times out with a fragment.
    // The sixth request is a clean 409 "already used", so only the fragments stand between this
    // and a finding built from five "accepted" replies that were never read in full.
    let n = 0;
    const port = await serve(async (req, res) => {
      await drain(req);
      n++;
      if (n > 5) return void res.writeHead(409, { "content-type": "application/json" }).end(`{"error":"Code already redeemed"}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.write(`{"data":{"credits":`);
    });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/rewards/claim`], credentials: CREDS, timeoutMs: 300 }));
    expect(out.findings).toEqual([]);
  });
});

describe("runRaceConditionProbe: false positives", () => {
  it("does not fire on a correct claim that answers 200 with 'already been used' to repeats", async () => {
    // First request wins; the rest are told so in the BODY of a 200. The first version's phrase list
    // had 'already used' but not 'already been used', counted all five as successes and raised HIGH.
    const port = await serve(atomicClaim((res) => res.writeHead(200, { "content-type": "application/json" }).end(`{"message":"Code has already been used"}`)));
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/reward/redeem`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
    expect(out.notTested).toBeUndefined();
  });

  it("does not fire on a claim that allows exactly one success", async () => {
    const port = await serve(atomicClaim());
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/gift/claim`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
    expect(out.notTested).toBeUndefined();
  });

  it("does not fire on an endpoint that accepts every repeat, including one sent after the burst", async () => {
    // Idempotent 'apply this code' or no enforcement at all: not a one-time action with a race in
    // it. The first version reported a HIGH race whose text claimed 'a discount applied repeatedly'.
    const port = await serve(async (req, res) => { await drain(req); res.writeHead(200, { "content-type": "application/json" }).end(`{"applied":true,"discount":"10%"}`); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
    expect(out.notTested).toBeUndefined();
  });

  it("does not fire when the control is rate limited rather than refused", async () => {
    let n = 0;
    const port = await serve(async (req, res) => { await drain(req); n++; if (n > 5) { res.writeHead(429).end("slow down"); return; } res.writeHead(200, { "content-type": "application/json" }).end(`{"ok":true}`); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
  });

  it.each([
    ["success:false", `{"success":false,"error":"Coupon code is required"}`],
    ["an unknown code", `{"error":"Invalid promo code"}`],
    ["valid:false", `{"valid":false}`],
  ])("does not fire on a 200 that reports %s to every request", async (_label, body) => {
    const port = await serve(async (req, res) => { await drain(req); res.writeHead(200, { "content-type": "application/json" }).end(body); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
  });
});

describe("runRaceConditionProbe: a clean result must mean something was exercised", () => {
  it("says nothing was tested when no claim endpoint exists", async () => {
    const port = await serve((_req, res) => { res.writeHead(404).end(); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/users`], credentials: CREDS }));
    expect(out.notTested).toMatch(/no claim-style endpoint/i);
  });

  it("says nothing was tested when every request was refused for want of a code, which an empty body cannot supply", async () => {
    // A real redeem route that needs a code answers 400 five times; only body-less claims are testable.
    const port = await serve(async (req, res) => { await drain(req); res.writeHead(400, { "content-type": "application/json" }).end(`{"error":"code is required"}`); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.findings).toEqual([]);
    expect(out.notTested).toMatch(/refused|needs|nothing was tested/i);
  });

  it("says nothing was tested when a 200 body refuses every request", async () => {
    const port = await serve(async (req, res) => { await drain(req); res.writeHead(200, { "content-type": "application/json" }).end(`{"success":false,"error":"Coupon code is required"}`); });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS }));
    expect(out.notTested).toBeDefined();
  });

  it("does not report notTested when at least one candidate was exercised", async () => {
    const port = await serve(async (req, res) => {
      await drain(req);
      if (req.url === "/api/a/redeem") { res.writeHead(400).end("no"); return; }
      res.writeHead(200, { "content-type": "application/json" }).end(`{"ok":true}`);
    });
    const out = await inScan(port, () => runRaceConditionProbeDetailed({
      endpoints: [`http://127.0.0.1:${port}/api/a/redeem`, `http://127.0.0.1:${port}/api/b/redeem`],
      credentials: CREDS,
    }));
    expect(out.notTested).toBeUndefined();
  });
});

describe("runRaceConditionProbe: bounded", () => {
  it("does not hang on a reply that never finishes", async () => {
    const port = await serve(async (req, res) => {
      await drain(req);
      res.writeHead(200, { "content-type": "application/json" });
      res.write("{");
      setTimeout(() => res.destroy(), 6_000).unref();
    });
    const started = Date.now();
    await inScan(port, () => runRaceConditionProbeDetailed({ endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`], credentials: CREDS, timeoutMs: 400 }));
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 20_000);

  it("sends at most five concurrent requests and one control to each of three endpoints", async () => {
    let n = 0;
    const port = await serve(async (req, res) => { n++; await drain(req); res.writeHead(200, { "content-type": "application/json" }).end(`{"ok":true}`); });
    const endpoints = Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:${port}/api/shop${i}/redeem`);
    await inScan(port, () => runRaceConditionProbeDetailed({ endpoints, credentials: CREDS }));
    expect(n).toBe(18);
  });
});
