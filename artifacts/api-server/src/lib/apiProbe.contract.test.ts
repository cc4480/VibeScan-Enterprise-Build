import { describe, it, expect } from "vitest";
import { serve, ep } from "./apiProbe.testkit";
import { runApiProbes } from "./apiProbe.js";
import { runWithScanHttp } from "./http.js";

describe("mass assignment, read from the declared contract", () => {
  it("reports a privilege field on a create endpoint the spec declares", async () => {
    // POST /api/users is not read-shaped, so nothing is ever sent to it; the finding is read from the spec.
    let requests = 0;
    const port = await serve((_req, res) => { requests++; res.writeHead(404); res.end(); });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/users`, method: "POST", source: "spec", params: [
          { name: "email", location: "body" }, { name: "role", location: "body" },
        ] })],
      }),
    );
    const f = findings.find((v) => v.name === "Privilege Fields Accepted in Request Bodies");
    expect(f?.evidence).toMatch(/POST \/api\/users\s+role/);
    expect(requests).toBe(0);
  });

  it("does not report a field the app's own bundle sends to a write endpoint", async () => {
    const port = await serve((_req, res) => { res.writeHead(404); res.end(); });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/comments`, method: "POST", source: "bundle", params: [
          { name: "user_id", location: "body" },
        ] })],
      }),
    );
    expect(findings.some((v) => v.name === "Privilege Fields Accepted in Request Bodies")).toBe(false);
  });
});

describe("rate-limit burst", () => {
  it("does not burst a session-state read that sits under /auth/", async () => {
    // NextAuth's /api/auth/session answers {} to everyone; twelve of those say nothing about brute force.
    const port = await serve((_req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/auth/session` })] }),
    );
    expect(findings.some((f) => /Rate Limiting Observed/i.test(f.name))).toBe(false);
  });
});
