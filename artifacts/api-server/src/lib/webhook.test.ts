import { describe, it, expect, beforeAll, afterAll } from "vitest";
import net, { type AddressInfo } from "node:net";
import { useRealDb, TEST_DATABASE_URL, openDb, uniqueEmail } from "./realDb.testkit";

useRealDb();
// Imported only now: the db module this pulls in must be built against the real database URL set above.
const { fireWebhook } = await import("./webhook");

/**
 * A monitor subscription takes a webhook URL from the user and the server then makes requests to it. That is server-side
 * request forgery by construction, and it is the exact class this scanner sells itself on finding in other people's
 * applications, so it would be a poor look to ship it.
 *
 * The control is correct today: https-only, host rules shared with the scan-target path so the two cannot drift, redirects
 * refused outright, and the check runs before anything is sent. None of that was tested, which is one refactor away from
 * being bypassed with nobody noticing: an SSRF guard fails silently by definition, because the successful attack looks
 * like a delivered webhook.
 *
 * Everything here is real. fireWebhook reports what happened (delivered, skipped, blocked, failed, and how many requests
 * it sent). A refusal is shown by that outcome and, where a listener can exist, by the listener never being contacted.
 * Deliveries go over the real internet to httpbin.org, a public service made for testing HTTP clients; those tests skip
 * when it cannot be reached. A webhook can never be delivered to this machine: the guard refuses private addresses
 * whatever ALLOW_PRIVATE_SCAN_TARGETS says, which is the point.
 */

const ECHO = "https://httpbin.org";
let online = false;
beforeAll(async () => {
  try {
    online = (await fetch(`${ECHO}/status/200`, { method: "POST", signal: AbortSignal.timeout(8_000) })).ok;
  } catch {
    online = false;
  }
}, 15_000);

async function fire(url: string, notify: { userId: string; severity?: string } = { userId: "user-1" }, event: Parameters<typeof fireWebhook>[1] = "scan_complete") {
  return fireWebhook(url, event, "https://example.com", "sub-1", { grade: "A" }, notify);
}
const BLOCKED = { status: "blocked_url", attempts: 0 };

describe("fireWebhook: hosts the guard must refuse", () => {
  it("refuses loopback, so a listener there never receives a connection", async () => {
    let connections = 0;
    const listener = net.createServer((s) => { connections++; s.destroy(); });
    await new Promise<void>((r) => listener.listen(0, "127.0.0.1", r));
    const port = (listener.address() as AddressInfo).port;
    try {
      for (const host of ["127.0.0.1", "localhost"]) expect(await fire(`https://${host}:${port}/hook`), host).toEqual(BLOCKED);
      expect(connections).toBe(0);
    } finally {
      await new Promise((r) => listener.close(r));
    }
  });

  it("refuses an IPv6 loopback address", async () => {
    expect(await fire("https://[::1]/hook")).toEqual(BLOCKED);
  });

  it("refuses RFC-1918 private ranges", async () => {
    for (const url of ["https://10.0.0.5/hook", "https://192.168.1.10/hook", "https://172.16.0.9/hook"]) {
      expect(await fire(url), url).toEqual(BLOCKED);
    }
  });

  it("refuses the cloud metadata address", async () => {
    // The single most valuable SSRF target on a hosted deployment: it serves instance credentials to anything that can reach it.
    expect(await fire("https://169.254.169.254/latest/meta-data/")).toEqual(BLOCKED);
  });

  it("is not opened by a self-hoster's ALLOW_PRIVATE_SCAN_TARGETS: that switch is for scan targets, not user-supplied webhooks", async () => {
    const saved = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    try {
      expect(await fire("https://127.0.0.1/hook")).toEqual(BLOCKED);
    } finally {
      if (saved === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
      else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = saved;
    }
  });

  it("refuses plain http even on a public host", async () => {
    // A webhook URL often carries a secret token in its path or query. Over http that token leaves in cleartext, so this
    // is refused on transport grounds rather than host grounds.
    expect(await fire("http://httpbin.org/post")).toEqual(BLOCKED);
  });

  it("refuses a URL that will not parse", async () => {
    for (const url of ["not-a-url", "", "javascript:alert(1)", "file:///etc/passwd"]) {
      expect(await fire(url), JSON.stringify(url)).toEqual(BLOCKED);
    }
  });
});

describe("fireWebhook: what it does deliver (the real internet, httpbin.org)", () => {
  it("posts to a legitimate https endpoint", async ({ skip }) => {
    if (!online) skip();
    // The control that makes every refusal above mean something: if nothing were ever delivered, all of those would
    // pass while proving nothing.
    expect(await fire(`${ECHO}/post`)).toEqual({ status: "delivered", attempts: 1 });
  });

  it("never follows a redirect", async ({ skip }) => {
    if (!online) skip();
    // A permitted host that answers 302 to somewhere else is the standard way around a hostname allowlist. Refusing
    // redirects outright closes it more firmly than re-checking each hop: followed, this would be 'delivered'.
    const out = await fire(`${ECHO}/redirect-to?url=${encodeURIComponent(`${ECHO}/post`)}&status_code=302`);
    expect(out).toEqual({ status: "failed", attempts: 1 });
  });

  it("retries once on a non-2xx, then gives up quietly", async ({ skip }) => {
    if (!online) skip();
    const started = Date.now();
    const out = await fire(`${ECHO}/status/500`);
    expect(out).toEqual({ status: "failed", attempts: 2 });
    expect(Date.now() - started).toBeGreaterThanOrEqual(1_000); // the pause between the two attempts
  }, 30_000);

  it("bounds the request so a hung endpoint cannot pin the worker, and a failure never reaches the caller", async ({ skip }) => {
    if (!online) skip();
    // httpbin holds this response for 15 seconds; the request's own limit is 10. Delivery runs inside the scan pipeline,
    // so a webhook nobody can reach must not turn a completed scan into a failed one: it comes back as an outcome.
    const started = Date.now();
    const out = await fire(`${ECHO}/delay/15`);
    const took = Date.now() - started;
    expect(out.status).toBe("failed");
    expect(took).toBeGreaterThan(9_000);
    expect(took).toBeLessThan(14_000);
  }, 40_000);
});

describe.skipIf(!TEST_DATABASE_URL)("fireWebhook: notification preferences (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  const users: string[] = [];

  async function userWith(prefs: Partial<typeof dbMod.usersTable.$inferInsert>) {
    const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email: uniqueEmail("hookprefs"), ...prefs }).returning({ id: dbMod.usersTable.id });
    users.push(u!.id);
    return u!.id;
  }

  beforeAll(async () => { dbMod = await openDb(); }, 60_000);
  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (users.length) await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    await dbMod?.pool?.end?.();
  });

  it("does not deliver a kind the user turned off", async () => {
    const userId = await userWith({ notifyScanCompleteOptedOut: true });
    expect(await fire(`${ECHO}/post`, { userId }, "scan_complete")).toEqual({ status: "skipped_preferences", attempts: 0 });
  });

  it("drops an alert under the severity floor", async () => {
    const userId = await userWith({ notifyMinSeverity: "high" });
    expect(await fire(`${ECHO}/post`, { userId, severity: "low" }, "cve_alert")).toEqual({ status: "skipped_preferences", attempts: 0 });
  });

  it("still delivers the kinds they kept", async ({ skip }) => {
    if (!online) skip();
    const userId = await userWith({ notifyScanCompleteOptedOut: true });
    expect(await fire(`${ECHO}/post`, { userId, severity: "high" }, "cve_alert")).toEqual({ status: "delivered", attempts: 1 });
  });

  it("ignores the EMAIL opt-out: that switch is not about webhooks", async ({ skip }) => {
    if (!online) skip();
    // One-click List-Unsubscribe sets alertEmailsOptedOut. If that also killed webhooks, a user tidying their inbox would
    // silently break their team's Slack integration, and nothing would say why.
    const userId = await userWith({ alertEmailsOptedOut: true });
    expect(await fire(`${ECHO}/post`, { userId, severity: "high" }, "cve_alert")).toEqual({ status: "delivered", attempts: 1 });
  });
});
