import { serve, OWNER, OTHER, who, loginPage, record } from "./accessControlProbe.testkit";
import { describe, it, expect } from "vitest";
import http from "node:http";
import { runWithScanHttp } from "./http.js";
import { runAccessControlProbes, mutateIdentifiers } from "./accessControlProbe.js";

describe("mutateIdentifiers", () => {
  it("walks a numeric path id to its neighbours", () => {
    const out = mutateIdentifiers("https://a.example/invoices/1042");
    expect(out).toContain("https://a.example/invoices/1043");
    expect(out).toContain("https://a.example/invoices/1041");
    expect(out).not.toContain("https://a.example/invoices/1042");
  });

  it("walks a numeric query id", () => {
    const out = mutateIdentifiers("https://a.example/invoice?id=7");
    expect(out).toContain("https://a.example/invoice?id=8");
    expect(out).toContain("https://a.example/invoice?id=6");
  });

  it("never produces a zero or negative id", () => {
    const out = mutateIdentifiers("https://a.example/items/1");
    expect(out.every((u) => !/\/items\/(0|-\d+)/.test(u))).toBe(true);
  });

  it("leaves UUIDs alone — guessing one is infeasible, which is the point of them", () => {
    expect(
      mutateIdentifiers("https://a.example/users/550e8400-e29b-41d4-a716-446655440000"),
    ).toEqual([]);
  });

  it("returns nothing for a URL with no numeric identifier", () => {
    expect(mutateIdentifiers("https://a.example/dashboard")).toEqual([]);
  });
});

describe("enumeration by identifier mutation", () => {
  it("reports records reachable by editing the id that nothing linked to", async () => {
    // Only invoice 1042 is ever linked. 1043 belongs to someone else and the
    // app returns it to anyone signed in.
    const port = await serve((req, res) => {
      const w = who(req);
      if (w === "anon") {
        res.writeHead(401, { "content-type": "text/html" });
        res.end(loginPage);
        return;
      }
      const id = /\/invoices\/(10\d\d)/.exec(req.url ?? "")?.[1];
      if (!id) {
        res.writeHead(404);
        res.end("no");
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record(`customer-of-invoice-${id}`));
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbes({
        urls: [`http://localhost:${port}/invoices/1042`],
        primary: OWNER,
        secondary: OTHER,
      }),
    );

    const enumerated = findings.find((f) => /Enumerable/i.test(f.name));
    expect(enumerated).toBeDefined();
    expect(enumerated!.severity).toBe("critical");
    // A neighbour the caller was never shown.
    expect(enumerated!.evidence).toMatch(/invoices\/104[13]/);
  });

  it("stays quiet when neighbouring records are properly refused", async () => {
    const port = await serve((req, res) => {
      const w = who(req);
      if (w === "anon") {
        res.writeHead(401);
        res.end(loginPage);
        return;
      }
      const id = /\/invoices\/(\d+)/.exec(req.url ?? "")?.[1];
      // Only 1042 belongs to the owner; everything else is another user's.
      if (id !== "1042" || w !== "owner") {
        res.writeHead(403);
        res.end("Forbidden");
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record("Ada"));
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbes({
        urls: [`http://localhost:${port}/invoices/1042`],
        primary: OWNER,
        secondary: OTHER,
      }),
    );

    expect(findings).toEqual([]);
  });

  it("never mutates into a destructive URL", async () => {
    const requested: string[] = [];
    const port = await serve((req, res) => {
      requested.push(req.url ?? "");
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record("Ada"));
    });

    await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbes({
        urls: [`http://localhost:${port}/invoices/1042/delete`],
        primary: OWNER,
        secondary: OTHER,
      }),
    );

    expect(requested).toEqual([]);
  });
});
