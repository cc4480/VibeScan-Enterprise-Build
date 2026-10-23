/**
 * The SSRF probe versus open redirects, with the real out-of-band loop: the probe plants a URL from the real token
 * registry, the app's own /api/oob router (served here on loopback) records whoever calls it in a REAL Postgres
 * (BILLING_TEST_DATABASE_URL), and the probe reads the interactions back. The tests can therefore tell who called:
 * the scanner's own redirect-follow, or the target's server. The probe really waits out its callback window.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "./realDb.testkit";
import { serve, closeServers } from "./testkit";

useRealDb();

dbSuiteOf(describe)("SSRF probe versus open redirects (real out-of-band loop)", () => {
  let dbMod: typeof import("@workspace/db");
  let runSsrfProbes: typeof import("./ssrfProbe").runSsrfProbes;
  let collector: Server;
  let sql: typeof import("drizzle-orm").sql;
  let scanId: string;

  /** Tokens that have been called back, read from the table the real route writes to. */
  const calledBack = async () => {
    const r = await dbMod.db.execute(sql`select distinct token from oob_interactions`);
    return new Set(r.rows.map((x) => (x as { token: string }).token));
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ sql } = await import("drizzle-orm"));
    // The real OOB route, on a real listener; the base URL is read when the module loads, so set it first.
    const express = (await import("express")).default;
    const { default: oobRouter } = await import("../routes/oob");
    const app = express();
    app.use("/api", oobRouter);
    collector = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => collector.once("listening", () => r()));
    process.env["OOB_BASE_URL"] = `http://127.0.0.1:${(collector.address() as AddressInfo).port}`;
    ({ runSsrfProbes } = await import("./ssrfProbe"));
    // Tokens belong to a scan, so the probe needs a real one.
    const [scan] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId: "ssrf-probe", userEmail: uniqueEmail("ssrf"), targetUrl: "http://localhost/", tier: "deep", status: "scanning" })
      .returning({ id: dbMod.scansTable.id });
    scanId = scan!.id;
  }, 60_000);

  afterEach(async () => {
    await closeServers();
    await dbMod.db.execute(sql`delete from oob_interactions`);
  });

  afterAll(async () => {
    collector?.close();
    if (scanId) await dbMod.db.delete(dbMod.scansTable).where(sql`id = ${scanId}`); // its tokens go with it
    delete process.env["OOB_BASE_URL"];
    await dbMod?.pool?.end?.();
  });

  const run = (targetUrl: string) => runSsrfProbes({ scanId, targetUrl, endpoints: [] });
  /** How many callback URLs the probe really planted for this scan: a probe that planted none proves nothing. */
  const planted = async () => Number(((await dbMod.db.execute(sql`select count(*)::int as n from oob_tokens where scan_id = ${scanId}`)).rows[0] as { n: number }).n);

  it.each(["next", "url", "redirect", "return_url", "callback"])(
    "does not report SSRF when the target only 302s to the %s parameter",
    async (param) => {
      const port = await serve((req, res) => {
        const dest = new URL(req.url!, "http://x").searchParams.get(param);
        res.writeHead(302, { Location: dest ?? "/" }).end();
      });
      expect(await run(`http://localhost:${port}/login?${param}=/home`)).toEqual([]);
      expect(await planted()).toBeGreaterThan(0);
      expect((await calledBack()).size).toBe(0);
    },
    60_000,
  );

  it("still reports SSRF when the target's server fetches the planted URL", async () => {
    const port = await serve((req, res) => {
      const dest = new URL(req.url!, "http://x").searchParams.get("url");
      if (dest) {
        http.get(dest, (r) => { r.resume(); res.writeHead(200).end("fetched"); })
          .on("error", () => res.writeHead(502).end());
      } else res.writeHead(200).end();
    });
    const found = await run(`http://localhost:${port}/preview?url=http://example.com`);
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toMatch(/SSRF/);
    expect((await calledBack()).size).toBeGreaterThan(0);
  }, 60_000);
});
