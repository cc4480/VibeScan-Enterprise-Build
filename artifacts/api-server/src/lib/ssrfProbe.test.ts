import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import type { ApiEndpoint } from "./apiSurface.js";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "./realDb.testkit";
import { serve as listen, closeServers } from "./testkit";

useRealDb();
// Imported only now: the db module this pulls in must be built against the real database URL set above.
const { isUrlParam } = await import("./ssrfProbe.js");

/**
 * The SSRF probe, with the real out-of-band loop: tokens come from the real registry, the app's own /api/oob route (served
 * here on loopback) records whoever calls it in a REAL Postgres (BILLING_TEST_DATABASE_URL), and the probe reads the
 * interactions back. A target "fetches" the planted URL for real, so a finding is only ever reported on a real callback.
 * The probe really waits out its callback window.
 */

function ep(partial: Partial<ApiEndpoint> & { url: string }): ApiEndpoint {
  return { method: "GET", params: [], source: "spec", ...partial };
}

describe("isUrlParam", () => {
  it.each(["url", "uri", "callback", "webhook", "redirect", "image_url", "feed", "proxy", "dest"])(
    "recognises %s",
    (name) => expect(isUrlParam(name)).toBe(true),
  );

  it.each(["quantity", "email", "name", "total", "id", "password"])(
    "ignores %s",
    (name) => expect(isUrlParam(name)).toBe(false),
  );
});

dbSuiteOf(describe)("runSsrfProbes (real out-of-band loop)", () => {
  let dbMod: typeof import("@workspace/db");
  let sql: typeof import("drizzle-orm").sql;
  let runSsrfProbes: typeof import("./ssrfProbe.js").runSsrfProbes;
  let collector: Server;
  let scanId: string;
  const savedBase = process.env["OOB_BASE_URL"];

  /** The callback URLs the probe planted for this scan: token and what it was planted in. */
  const planted = async () =>
    (await dbMod.db.execute(sql`select token, context from oob_tokens where scan_id = ${scanId}`)).rows as Array<{ token: string; context: string }>;
  const calledBack = async () =>
    new Set(((await dbMod.db.execute(sql`select distinct token from oob_interactions`)).rows as Array<{ token: string }>).map((r) => r.token));

  beforeAll(async () => {
    dbMod = await openDb();
    ({ sql } = await import("drizzle-orm"));
    const express = (await import("express")).default;
    const { default: oobRouter } = await import("../routes/oob");
    const app = express();
    app.use("/api", oobRouter);
    collector = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => collector.once("listening", () => r()));
    process.env["OOB_BASE_URL"] = `http://127.0.0.1:${(collector.address() as AddressInfo).port}`;
    ({ runSsrfProbes } = await import("./ssrfProbe.js"));
    const [scan] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId: "ssrf-probe-2", userEmail: uniqueEmail("ssrf2"), targetUrl: "http://localhost/", tier: "deep", status: "scanning" })
      .returning({ id: dbMod.scansTable.id });
    scanId = scan!.id;
  }, 60_000);

  afterEach(async () => {
    await closeServers();
    await dbMod.db.execute(sql`delete from oob_interactions`);
    await dbMod.db.execute(sql`delete from oob_tokens where scan_id = ${scanId}`);
    if (savedBase === undefined) process.env["OOB_BASE_URL"] = `http://127.0.0.1:${(collector.address() as AddressInfo).port}`;
    else process.env["OOB_BASE_URL"] = savedBase;
  });

  afterAll(async () => {
    collector?.close();
    if (scanId) await dbMod.db.delete(dbMod.scansTable).where(sql`id = ${scanId}`);
    if (savedBase === undefined) delete process.env["OOB_BASE_URL"];
    else process.env["OOB_BASE_URL"] = savedBase;
    await dbMod?.pool?.end?.();
  });

  /** A target that does nothing with what it is sent. */
  const idle = () => listen((_req, res) => { res.writeHead(200); res.end("ok"); });
  /** A vulnerable target: it fetches whatever address its `url` or `webhook` parameter holds. */
  const fetchesParams = () =>
    listen((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      const dest = u.searchParams.get("url") ?? u.searchParams.get("webhook");
      if (dest) {
        http.get(dest, (r) => { r.resume(); res.writeHead(200).end("fetched"); }).on("error", () => res.writeHead(502).end());
      } else res.writeHead(200).end("ok");
    });
  const run = (input: { targetUrl: string; endpoints: ApiEndpoint[] }) => runSsrfProbes({ scanId, ...input });

  it("does nothing when no collector is configured", async () => {
    delete process.env["OOB_BASE_URL"];
    const savedOrigin = process.env["APP_ORIGIN"];
    delete process.env["APP_ORIGIN"];
    try {
      expect(await runSsrfProbes({ scanId, targetUrl: "https://a.example/?url=x", endpoints: [] })).toEqual([]);
      expect(await planted()).toEqual([]);
    } finally {
      if (savedOrigin !== undefined) process.env["APP_ORIGIN"] = savedOrigin;
    }
  });

  it("plants a callback URL in a url-shaped query parameter", async () => {
    const port = await idle();
    await run({ targetUrl: `http://localhost:${port}/fetch?url=http://original`, endpoints: [] });
    const rows = await planted();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.context).toContain('"url"');
  }, 60_000);

  it("leaves parameters that do not carry a URL alone", async () => {
    const port = await idle();
    await run({ targetUrl: `http://localhost:${port}/search?q=hello&count=5`, endpoints: [] });
    // "q" is in the URL_PARAM set (a common SSRF alias); "count" is not.
    expect((await planted()).every((r) => !r.context.includes('"count"'))).toBe(true);
  }, 60_000);

  it("reports SSRF only when a callback actually arrived", async () => {
    // A target that never fetches what it is given: tokens are planted, no callback arrives, nothing is reported.
    const quiet = await idle();
    let found = await run({ targetUrl: `http://localhost:${quiet}/fetch?url=x`, endpoints: [] });
    expect(found).toEqual([]);
    expect((await planted()).length).toBeGreaterThan(0);
    expect((await calledBack()).size).toBe(0);

    // A target that fetches the planted address: the real collector sees the call, and only now is it reported.
    await closeServers();
    const vulnerable = await fetchesParams();
    found = await run({ targetUrl: `http://localhost:${vulnerable}/fetch?url=x`, endpoints: [] });
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toMatch(/SSRF/);
    expect(found[0]!.severity).toBe("critical");
    expect(found[0]!.cweId).toBe("CWE-918");
    expect((await calledBack()).size).toBeGreaterThan(0);
  }, 90_000);

  it("tests url-shaped parameters declared by API endpoints", async () => {
    const port = await idle();
    await run({
      targetUrl: `http://localhost:${port}/`,
      endpoints: [
        ep({
          url: `http://localhost:${port}/api/import`,
          params: [
            { name: "webhook", location: "query" },
            { name: "count", location: "query" },
          ],
        }),
      ],
    });
    const rows = await planted();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.context).toContain('"webhook"');
  }, 60_000);

  it("never plants a payload in a destructive endpoint", async () => {
    const port = await idle();
    await run({
      targetUrl: `http://localhost:${port}/`,
      endpoints: [
        ep({
          url: `http://localhost:${port}/api/account/delete`,
          params: [{ name: "url", location: "query" }],
        }),
      ],
    });
    expect(await planted()).toEqual([]);
  }, 60_000);
});
