import { describe, it, expect, beforeEach, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { TestLedger, NOT_VERIFIED } from "./testLedger";
import { runCrossAccountStep, type CrossAccountStepInput } from "./crossAccountStep";
import { runWithScanHttp } from "./http";

/**
 * The scanner's cross-account step, run for real against a small shop on a real loopback server: the real signup attempt
 * and the real access-control comparison make real requests. It was inline in scanner.ts with no test, and reviewers found
 * it did five things wrong: it created an account on the customer's site before knowing the probe could use it, it
 * recorded "ran" for a test that compared nothing, it worded a submitted signup as "nothing was created", it left the
 * owner no trace of the account, and an unexpected error there was recorded as a plain skip.
 *
 * Not covered: the step's handling of an exception thrown out of the signup attempt or the comparison. Both are written
 * never to throw (every failure comes back as a result), so there is no real input that makes them.
 */

const NAME = "cross-account access control (IDOR)";
const PRIMARY = { cookie: "sid=alice" };
const OWN_SECOND = { cookie: "sid=bob" };
const EMAIL = /secscan-test-[0-9a-f]+@example\.com/;

/** What the shop does, changed per test. */
const shop = {
  /** What posting the signup form gives: a session, nothing, or a request to verify the email address. */
  signup: "session" as "session" | "none" | "verify" | "absent",
  /** Whether any signed-in visitor can read alice's order (the access-control hole). */
  idor: false,
  /** Whether alice can read her own order at all. */
  aliceCanRead: true,
  posted: [] as string[],
  hits: [] as string[],
};

const ORDER = `<html><body><h1>Order 1042</h1>
  <p>Customer Alice of Acme Industries, billing address 14 Rowan Street Bristol</p>
  <p>Line items: consulting retainer, hosting, support hours, travel expenses</p>
  <p>Totals: subtotal 4200, tax 840, due 5040, payable within thirty days</p></body></html>`;

const server = http.createServer((req, res) => {
  shop.hits.push(`${req.method} ${req.url}`);
  const cookie = req.headers.cookie ?? "";
  const signedIn = /sid=(alice|bob|auto)/.test(cookie);
  const html = (status: number, body: string, extra: Record<string, string> = {}): void => {
    res.writeHead(status, { "content-type": "text/html", ...extra }).end(body);
  };

  if (req.url === "/signup" && shop.signup !== "absent") {
    if (req.method === "GET") {
      html(200, `<h1>Sign up</h1><form method="POST" action="/signup"><input type="email" name="email"><input type="password" name="password"><button>Create account</button></form>`);
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      shop.posted.push(decodeURIComponent(body));
      if (shop.signup === "session") html(302, "", { location: "/dashboard", "set-cookie": "sid=auto; Path=/" });
      else if (shop.signup === "verify") html(200, "<p>Thanks! Please verify your email address to continue: check your inbox for the confirmation link.</p>");
      else html(200, "<p>Thanks, we will be in touch.</p>");
    });
    return;
  }
  if (req.url === "/dashboard") {
    if (signedIn) html(200, "<h1>Your dashboard</h1><p>Orders, invoices and team members.</p>");
    else html(302, "", { location: "/signup" });
    return;
  }
  if (req.url === "/") {
    html(200, "<h1>Acme shop</h1><p>Welcome to the shop.</p>");
    return;
  }
  if (req.url === "/orders/1042") {
    if (!signedIn) html(401, "<h1>Please log in</h1><form><input type='password' name='p'></form>");
    else if (/sid=alice/.test(cookie)) {
      if (shop.aliceCanRead) html(200, ORDER);
      else html(404, "Not found");
    } else if (shop.idor) html(200, ORDER);
    else html(403, "Forbidden");
    return;
  }
  html(404, "Not found");
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const ORIGIN = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
afterAll(() => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }));

beforeEach(() => {
  shop.signup = "session";
  shop.idor = false;
  shop.aliceCanRead = true;
  shop.posted.length = 0;
  shop.hits.length = 0;
});

function harness(over: Partial<CrossAccountStepInput> = {}) {
  const ledger = new TestLedger();
  const unrun: string[] = [];
  const input: CrossAccountStepInput = {
    allowActiveProbes: true,
    // The scan asked for an automatic account; the opt-in tests below turn it off.
    allowAutoAccount: true,
    primary: PRIMARY,
    finalUrl: `${ORIGIN}/`,
    pagesVisited: [`${ORIGIN}/orders/1042`, `${ORIGIN}/dashboard`],
    ledger,
    unrunFamilies: unrun,
    ...over,
  };
  const run = () => runWithScanHttp({ targetUrl: `${ORIGIN}/` }, () => runCrossAccountStep(input));
  return { ledger, unrun, input, run };
}

const PLAIN_PAGES = [`${ORIGIN}/dashboard`, `${ORIGIN}/settings`];

describe("runCrossAccountStep: the automatic account is opt-in", () => {
  for (const [label, value] of [["not asked for (the default)", undefined], ["explicitly off", false]] as const) {
    it(`submits no signup form when it was ${label}, and says why in the coverage list`, async () => {
      const h = harness({ allowAutoAccount: value });
      const out = await h.run();
      expect(shop.posted).toEqual([]);
      expect(shop.hits).toEqual([]);
      expect(out).toEqual([]);
      const rec = h.ledger.records.find((r) => r.name === NAME);
      expect(rec?.status).toBe("skipped");
      expect(rec?.reason).toMatch(/not requested for this scan.*opt-in.*signup form/);
    });
  }

  it("still runs the comparison with a supplied second account when the option is off", async () => {
    const h = harness({ allowAutoAccount: false, secondary: OWN_SECOND });
    await h.run();
    expect(shop.posted).toEqual([]);
    expect(shop.hits.some((x) => x.startsWith("GET /orders/1042"))).toBe(true);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran" });
  });
});

describe("runCrossAccountStep: gating", () => {
  it("skips with the standard reason, and touches nothing, on an unverified domain", async () => {
    const h = harness({ allowActiveProbes: false });
    expect(await h.run()).toEqual([]);
    expect(shop.hits).toEqual([]);
    expect(h.ledger.records).toEqual([expect.objectContaining({ name: NAME, status: "skipped", reason: NOT_VERIFIED })]);
  });

  it("skips without a signed-in primary account, and creates nothing", async () => {
    const h = harness({ primary: undefined });
    await h.run();
    expect(shop.hits).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped", reason: "needs sign-ins for two test accounts on the scan" });
  });

  it("does NOT create an account when no URL names a record, and says why", async () => {
    // The probe filters to record-shaped URLs and returns [] when none remain, so the account
    // would have been created on the customer's system for a test that then had nothing to do.
    const h = harness({ pagesVisited: PLAIN_PAGES });
    await h.run();
    expect(shop.posted).toEqual([]);
    expect(shop.hits).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toMatch(/no URL naming a specific record/);
  });

  it("also skips, honestly, when the user supplied a second account but there is nothing to compare", async () => {
    const h = harness({ secondary: OWN_SECOND, pagesVisited: PLAIN_PAGES });
    await h.run();
    expect(shop.hits).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
  });

  it("never auto-creates an account when the primary signs in with headers rather than a cookie", async () => {
    // A cookie from an HTML form is not comparable with a bearer-token identity: the probe would
    // run with the wrong kind of second account and read clean.
    const h = harness({ primary: { headers: { Authorization: "Bearer x" } } });
    await h.run();
    expect(shop.posted).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toMatch(/cookie/i);
  });

  it("does not attempt a signup when the user supplied a second account", async () => {
    const h = harness({ secondary: OWN_SECOND });
    await h.run();
    expect(shop.posted).toEqual([]);
    expect(shop.hits.some((x) => x.startsWith("GET /signup"))).toBe(false);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran" });
  });
});

describe("runCrossAccountStep: an automatic account", () => {
  it("uses the created account, marks it auto-created, and tells the owner it exists", async () => {
    const h = harness();
    const out = await h.run();
    expect(shop.posted).toHaveLength(1);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran", findings: 0 });
    const notice = out.find((v) => /test account (was|may have been) created/i.test(v.name));
    expect(notice).toBeDefined();
    expect(notice!.category).toBe("Scan Coverage");
    expect(notice!.severity).toBe("info");
    // The address in the notice is the one the form really received.
    const sent = EMAIL.exec(shop.posted[0]!)![0];
    expect(notice!.evidence).toContain(sent);
    expect(notice!.solution).toMatch(/delete/i);
  });

  it("reports the access-control hole through the account it made, and still names the account", async () => {
    shop.idor = true;
    const h = harness();
    const out = await h.run();
    expect(out.some((v) => v.category === "Broken Access Control")).toBe(true);
    expect(out.some((v) => /test account (was|may have been) created/i.test(v.name))).toBe(true);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran" });
    expect(h.ledger.records[0]!.findings).toBeGreaterThan(0);
  });

  it("still tells the owner when a signup was submitted but produced no usable session", async () => {
    // Reviewers: up to six accounts could be created per scan with nothing in the report about them.
    shop.signup = "none";
    const h = harness();
    const out = await h.run();
    const notice = out.find((v) => /test account (was|may have been) created/i.test(v.name));
    const sent = EMAIL.exec(shop.posted[0]!)![0];
    expect(notice?.evidence).toContain(sent);
    expect(notice?.description).toMatch(/did not|not used|no session/i);
    const rec = h.ledger.records[0]!;
    expect(rec.status).toBe("skipped");
    // The reason must not claim that nothing was attempted.
    expect(rec.reason).toMatch(/submitted/);
    expect(rec.reason).toContain(sent);
    expect(rec.reason).not.toMatch(/no self-serve signup form/);
  });

  it("explains an email-verification wall and still names the account it may have made", async () => {
    shop.signup = "verify";
    const h = harness();
    const out = await h.run();
    expect(shop.posted).toHaveLength(1);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toMatch(/email verification/);
    expect(out.some((v) => /test account may have been created/i.test(v.name))).toBe(true);
  });

  it("adds no notice when no form was submitted, since nothing was created", async () => {
    shop.signup = "absent";
    const h = harness();
    const out = await h.run();
    expect(out).toEqual([]);
    expect(shop.posted).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toContain("no self-serve signup form");
  });
});

describe("runCrossAccountStep: what the comparison reports", () => {
  it("records a comparison that found nothing as ran", async () => {
    const h = harness({ secondary: OWN_SECOND });
    expect(await h.run()).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran", findings: 0 });
  });

  it("records a test that compared nothing as skipped, with a reason, not as a clean run", async () => {
    shop.aliceCanRead = false; // the first account cannot read the record, so there is nothing to compare against
    const h = harness({ secondary: OWN_SECOND });
    await h.run();
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped", findings: 0 });
    expect(h.ledger.records[0]!.reason).toMatch(/nothing was compared|could not be compared/i);
  });

  it("passes findings through", async () => {
    shop.idor = true;
    const h = harness({ secondary: OWN_SECOND });
    const out = await h.run();
    expect(out.length).toBeGreaterThan(0);
    expect(out.every((v) => v.category === "Broken Access Control")).toBe(true);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran", findings: out.length });
  });

  it("refuses to compare an account with itself", async () => {
    const h = harness({ secondary: PRIMARY });
    expect(await h.run()).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toMatch(/same account/);
  });
});
