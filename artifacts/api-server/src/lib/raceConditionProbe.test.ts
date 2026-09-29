import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { runRaceConditionProbe } from "./raceConditionProbe.js";

const servers: http.Server[] = [];

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

describe("runRaceConditionProbe", () => {
  it("ignores endpoints that don't look like a one-time claim action", async () => {
    const findings = await runRaceConditionProbe({
      endpoints: ["http://x/api/users", "http://x/api/orders/1"],
      credentials: { cookie: "sid=abc" },
    });
    expect(findings).toEqual([]);
  });

  it("flags a coupon endpoint that lets concurrent requests all succeed", async () => {
    const port = await serve((req, res) => {
      if (req.url === "/api/coupon/redeem" && req.method === "POST") {
        // Deliberately unsafe: no locking, every concurrent request "succeeds".
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, discount: "10%" }));
        return;
      }
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const findings = await runWithScanHttp({ targetUrl }, () =>
      runRaceConditionProbe({
        endpoints: [`http://127.0.0.1:${port}/api/coupon/redeem`],
        credentials: { cookie: "sid=abc" },
      }),
    );

    expect(findings.length).toBe(1);
    expect(findings[0]!.cweId).toBe("CWE-362");
    expect(findings[0]!.severity).toBe("high");
  });

  it("does not fire when the endpoint correctly rejects repeat attempts", async () => {
    let used = false;
    const port = await serve((req, res) => {
      if (req.url === "/api/promo/apply-code" && req.method === "POST") {
        if (used) {
          res.writeHead(409, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "code already used" }));
          return;
        }
        used = true;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const findings = await runWithScanHttp({ targetUrl }, () =>
      runRaceConditionProbe({
        endpoints: [`http://127.0.0.1:${port}/api/promo/apply-code`],
        credentials: { cookie: "sid=abc" },
      }),
    );

    // A correctly-guarded endpoint may still race one request through before
    // the guard engages; the important thing is it does not let most through.
    expect(findings).toEqual([]);
  });

  it("caps the number of candidate endpoints it will test", async () => {
    let requestCount = 0;
    const port = await serve((req, res) => {
      if (req.method === "POST" && req.url?.includes("redeem")) {
        requestCount++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const endpoints = Array.from({ length: 10 }, (_, i) => `http://127.0.0.1:${port}/api/redeem-${i}`);
    await runWithScanHttp({ targetUrl }, () =>
      runRaceConditionProbe({ endpoints, credentials: { cookie: "sid=abc" } }),
    );

    // At most 3 candidates × 5 concurrent attempts each.
    expect(requestCount).toBeLessThanOrEqual(15);
  });
});
