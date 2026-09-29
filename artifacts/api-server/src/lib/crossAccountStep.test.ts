import { describe, it, expect, vi } from "vitest";
import { TestLedger, NOT_VERIFIED } from "./testLedger";
import { runCrossAccountStep } from "./crossAccountStep";

/**
 * The scanner's cross-account step, driven with the two network-touching pieces stubbed. It was
 * inline in scanner.ts with no test, and reviewers found it did five things wrong: it created an
 * account on the customer's site before knowing the probe could use it, it recorded "ran" for a
 * test that compared nothing, it worded a submitted signup as "nothing was created", it left the
 * owner no trace of the account, and an unexpected error there was recorded as a plain skip.
 */

const NAME = "cross-account access control (IDOR)";
const PRIMARY = { cookie: "sid=alice" };
const OWN_SECOND = { cookie: "sid=bob" };
const RECORD_PAGES = ["https://shop.example/orders/1042", "https://shop.example/dashboard"];
const PLAIN_PAGES = ["https://shop.example/dashboard", "https://shop.example/settings"];

function harness(over: {
  attempt?: ReturnType<typeof vi.fn>;
  probe?: ReturnType<typeof vi.fn>;
} = {}) {
  const attempt = over.attempt ?? vi.fn(async () => ({ secondary: { cookie: "sid=auto" } }));
  const probe = over.probe ?? vi.fn(async () => ({ findings: [], compared: 2 }));
  const ledger = new TestLedger();
  const unrun: string[] = [];
  const base = {
    allowActiveProbes: true,
    primary: PRIMARY as { cookie?: string; headers?: Record<string, string> } | undefined,
    secondary: undefined as typeof OWN_SECOND | undefined,
    finalUrl: "https://shop.example/",
    pagesVisited: RECORD_PAGES,
    ledger,
    unrunFamilies: unrun,
  };
  return { attempt, probe, ledger, unrun, base, deps: { attempt: attempt as never, probe: probe as never } };
}

describe("runCrossAccountStep: gating", () => {
  it("skips with the standard reason, and touches nothing, on an unverified domain", async () => {
    const h = harness();
    const out = await runCrossAccountStep({ ...h.base, allowActiveProbes: false }, h.deps);
    expect(out).toEqual([]);
    expect(h.attempt).not.toHaveBeenCalled();
    expect(h.probe).not.toHaveBeenCalled();
    expect(h.ledger.records).toEqual([expect.objectContaining({ name: NAME, status: "skipped", reason: NOT_VERIFIED })]);
  });

  it("skips without a signed-in primary account, and creates nothing", async () => {
    const h = harness();
    await runCrossAccountStep({ ...h.base, primary: undefined }, h.deps);
    expect(h.attempt).not.toHaveBeenCalled();
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped", reason: "needs sign-ins for two test accounts on the scan" });
  });

  it("does NOT create an account when no URL names a record, and says why", async () => {
    // The probe filters to record-shaped URLs and returns [] when none remain, so the account
    // would have been created on the customer's system for a test that then had nothing to do.
    const h = harness();
    await runCrossAccountStep({ ...h.base, pagesVisited: PLAIN_PAGES }, h.deps);
    expect(h.attempt).not.toHaveBeenCalled();
    expect(h.probe).not.toHaveBeenCalled();
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toMatch(/no URL naming a specific record/);
  });

  it("also skips, honestly, when the user supplied a second account but there is nothing to compare", async () => {
    const h = harness();
    await runCrossAccountStep({ ...h.base, secondary: OWN_SECOND, pagesVisited: PLAIN_PAGES }, h.deps);
    expect(h.probe).not.toHaveBeenCalled();
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
  });

  it("never auto-creates an account when the primary signs in with headers rather than a cookie", async () => {
    // A cookie from an HTML form is not comparable with a bearer-token identity: the probe would
    // run with the wrong kind of second account and read clean.
    const h = harness();
    await runCrossAccountStep({ ...h.base, primary: { headers: { Authorization: "Bearer x" } } }, h.deps);
    expect(h.attempt).not.toHaveBeenCalled();
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toMatch(/cookie/i);
  });

  it("does not attempt a signup when the user supplied a second account", async () => {
    const h = harness();
    await runCrossAccountStep({ ...h.base, secondary: OWN_SECOND }, h.deps);
    expect(h.attempt).not.toHaveBeenCalled();
    expect(h.probe).toHaveBeenCalledWith(expect.objectContaining({ secondary: OWN_SECOND, secondaryAutoCreated: false }));
  });
});

describe("runCrossAccountStep: an automatic account", () => {
  it("uses the created account, marks it auto-created, and tells the owner it exists", async () => {
    const h = harness({
      attempt: vi.fn(async () => ({ secondary: { cookie: "sid=auto" }, submitted: true, email: "secscan-test-aa11bb22cc33@example.com" })),
    });
    const out = await runCrossAccountStep(h.base, h.deps);
    expect(h.probe).toHaveBeenCalledWith(expect.objectContaining({ secondary: { cookie: "sid=auto" }, secondaryAutoCreated: true }));
    const notice = out.find((v) => /test account (was|may have been) created/i.test(v.name));
    expect(notice).toBeDefined();
    expect(notice!.category).toBe("Scan Coverage");
    expect(notice!.severity).toBe("info");
    expect(notice!.evidence).toContain("secscan-test-aa11bb22cc33@example.com");
    expect(notice!.solution).toMatch(/delete/i);
  });

  it("still tells the owner when a signup was submitted but produced no usable session", async () => {
    // Reviewers: up to six accounts could be created per scan with nothing in the report about them.
    const h = harness({
      attempt: vi.fn(async () => ({
        secondary: null,
        skippedReason: "the signup form was submitted once but no session cookie came back",
        submitted: true,
        email: "secscan-test-ddeeff112233@example.com",
      })),
    });
    const out = await runCrossAccountStep(h.base, h.deps);
    expect(h.probe).not.toHaveBeenCalled();
    const notice = out.find((v) => /test account (was|may have been) created/i.test(v.name));
    expect(notice?.evidence).toContain("secscan-test-ddeeff112233@example.com");
    expect(notice?.description).toMatch(/did not|not used|no session/i);
    const rec = h.ledger.records[0]!;
    expect(rec.status).toBe("skipped");
    // The reason must not claim that nothing was attempted.
    expect(rec.reason).toMatch(/submitted/);
    expect(rec.reason).toMatch(/ddeeff112233@example\.com/);
    expect(rec.reason).not.toMatch(/no self-serve signup form/);
  });

  it("adds no notice when no form was submitted, since nothing was created", async () => {
    const h = harness({
      attempt: vi.fn(async () => ({ secondary: null, skippedReason: "no self-serve signup form granting an immediate session was found" })),
    });
    const out = await runCrossAccountStep(h.base, h.deps);
    expect(out).toEqual([]);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped" });
    expect(h.ledger.records[0]!.reason).toContain("no self-serve signup form");
  });

  it("does not let an error inside the signup attempt masquerade as a skip", async () => {
    const h = harness({ attempt: vi.fn(async () => { throw new Error("boom"); }) });
    const out = await runCrossAccountStep(h.base, h.deps);
    expect(out).toEqual([]);
    expect(h.unrun).toContain(NAME);
    expect(h.ledger.records[0]).toMatchObject({ status: "failed" });
  });
});

describe("runCrossAccountStep: what the probe reports", () => {
  it("records a comparison that found nothing as ran", async () => {
    const h = harness({ probe: vi.fn(async () => ({ findings: [], compared: 2 })) });
    await runCrossAccountStep({ ...h.base, secondary: OWN_SECOND }, h.deps);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran", findings: 0 });
  });

  it("records a test that compared nothing as skipped, with a reason, not as a clean run", async () => {
    const h = harness({ probe: vi.fn(async () => ({ findings: [], compared: 0 })) });
    await runCrossAccountStep({ ...h.base, secondary: OWN_SECOND }, h.deps);
    expect(h.ledger.records[0]).toMatchObject({ status: "skipped", findings: 0 });
    expect(h.ledger.records[0]!.reason).toMatch(/nothing was compared|could not be compared/i);
  });

  it("passes findings through", async () => {
    const f = { id: "1", name: "Broken Object-Level Authorisation (IDOR)", severity: "critical", category: "Broken Access Control", description: "d", solution: "s" };
    const h = harness({ probe: vi.fn(async () => ({ findings: [f], compared: 1 })) });
    const out = await runCrossAccountStep({ ...h.base, secondary: OWN_SECOND }, h.deps);
    expect(out).toEqual([f]);
    expect(h.ledger.records[0]).toMatchObject({ status: "ran", findings: 1 });
  });

  it("records a probe that threw as failed and lists the family as not completed", async () => {
    const h = harness({ probe: vi.fn(async () => { throw new Error("net down"); }) });
    const out = await runCrossAccountStep({ ...h.base, secondary: OWN_SECOND }, h.deps);
    expect(out).toEqual([]);
    expect(h.unrun).toEqual([NAME]);
    expect(h.ledger.records[0]).toMatchObject({ status: "failed", reason: "net down" });
  });
});
