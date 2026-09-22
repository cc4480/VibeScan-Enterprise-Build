import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * A scan whose owner deleted their account must stop, and it must stop before
 * the step that costs money.
 *
 * Deleting an account removes its scan rows (routes/account.ts) before the user
 * row, and reports.scan_id carries the only foreign key involved, so a job whose
 * scan id no longer resolves can never store a report. Before the guards these
 * tests cover, such a job ran the entire scan and then paid for a DeepSeek call,
 * failing only at the insert. Measured, not theorised: a concurrency test that
 * queued 20 scans and deleted the accounts seconds later saw 18 of them reach
 * DeepSeek before dying on that foreign key.
 *
 * Both tests assert an absence — that the expensive thing was never called — so
 * each one also asserts the job returned, otherwise "never called" would also
 * pass for a job that crashed on the line before.
 */

/** What db.update(...).returning() resolves to next, per call, in order. */
const updateReturns: unknown[][] = [];
const selectRows: unknown[][] = [];

const callLog = {
  runScan: 0,
  callDeepSeek: 0,
  insertReport: 0,
};

vi.mock("@workspace/db", () => {
  const updateChain = {
    set: () => updateChain,
    where: () => updateChain,
    returning: () => Promise.resolve(updateReturns.shift() ?? [{ id: "scan-1" }]),
    then: (resolve: (v: unknown) => unknown) => resolve(undefined),
  };
  const selectChain = {
    from: () => selectChain,
    where: () => Promise.resolve(selectRows.shift() ?? []),
    limit: () => Promise.resolve(selectRows.shift() ?? []),
  };
  const insertChain = {
    values: () => insertChain,
    returning: () => {
      callLog.insertReport += 1;
      return Promise.resolve([{ id: "report-1", userId: "user-1" }]);
    },
  };
  return {
    db: {
      update: () => updateChain,
      select: () => selectChain,
      insert: () => insertChain,
    },
    scansTable: { id: "id", userId: "user_id", credentialsEncrypted: "creds", secondaryCredentialsEncrypted: "creds2", userEmail: "user_email" },
    reportsTable: {},
    monitorSubscriptionsTable: {},
    dismissedFindingsTable: { userId: "user_id", targetUrl: "target_url", findingFingerprint: "fp" },
    monitorScoreHistoryTable: {},
    monitorRegressionsTable: {},
    usersTable: {},
  };
});

vi.mock("drizzle-orm", () => ({
  eq: () => ({}),
  and: () => ({}),
  desc: () => ({}),
  ne: () => ({}),
}));

vi.mock("./scanner", () => ({
  runScan: () => {
    callLog.runScan += 1;
    return Promise.resolve({
      vulnerabilities: [],
      technologies: [],
      server: null,
      tlsGrade: null,
      pagesScanned: [],
      probedNotFound: [],
      finalUrl: "https://example.com/",
      requestDurationMs: 10,
      intercepted: false,
    });
  },
  computeRiskScore: () => 0,
  gradeForResult: () => "A",
}));

vi.mock("./deepseek", () => ({
  callDeepSeek: () => {
    callLog.callDeepSeek += 1;
    return Promise.resolve(null);
  },
}));

vi.mock("./ssllabs", () => ({ checkSslLabs: () => Promise.resolve(null) }));
vi.mock("./recon", () => ({ runRecon: () => Promise.resolve(null) }));
vi.mock("./activeProbeGate", () => ({ activeProbesUnlocked: () => Promise.resolve(false) }));
vi.mock("./http", () => ({ runWithScanHttp: (_c: unknown, fn: () => unknown) => fn() }));
vi.mock("./reprobe", () => ({ reprobe: (_u: unknown, v: unknown) => Promise.resolve(v) }));
vi.mock("./scoring", () => ({ corroborateMerge: (v: unknown) => v }));
vi.mock("./fingerprint", () => ({
  findingFingerprint: () => "fp",
  canonicalizeTargetUrl: (u: string) => u,
}));
vi.mock("./scanCredentials", () => ({
  decryptCredentials: () => null,
  toScanHttpCredentials: () => Promise.resolve(null),
  looksSignedOut: () => false,
}));
vi.mock("./compliance", () => ({ summariseCompliance: () => [], COMPLIANCE_DISCLAIMER: "" }));
vi.mock("./monitorScheduler", () => ({ computeNextScanAt: () => new Date() }));
vi.mock("./mailer", () => ({
  sendReportReadyEmail: () => Promise.resolve(),
  sendRegressionAlertEmail: () => Promise.resolve(),
}));
vi.mock("./webhook", () => ({ fireWebhook: () => Promise.resolve() }));
vi.mock("./reportShare", () => ({ createReportShare: () => Promise.resolve({ token: "t" }), shareUrl: () => "u" }));
vi.mock("./queue", () => ({ getBoss: () => ({}), SCAN_QUEUE: "scan-job" }));
vi.mock("./oobServer", () => ({ purgeExpiredOobTokens: () => Promise.resolve() }));
vi.mock("./cveCheck", () => ({ warnIfLocalDataStale: () => {}, OSV_CACHE_MAX_SIZE: 1000 }));
vi.mock("./eolFetcher", () => ({
  refreshEolData: () => Promise.resolve(),
  loadEolCacheFromDb: () => Promise.resolve(),
  EOL_REFRESH_QUEUE: "eol-refresh",
}));
vi.mock("./browser", () => ({ initBrowser: () => Promise.resolve(), closeBrowser: () => Promise.resolve() }));
vi.mock("./appOrigin", () => ({ APP_ORIGIN: "https://secscan.us" }));
vi.mock("./logger", () => ({
  logger: { child: () => ({ info: () => {}, warn: () => {}, error: () => {} }) },
}));

const job = {
  data: {
    scanId: "scan-1",
    userId: "user-1",
    targetUrl: "https://example.com",
    tier: "deep",
  },
} as never;

async function load() {
  return import("./worker.js");
}

beforeEach(() => {
  vi.resetModules();
  updateReturns.length = 0;
  selectRows.length = 0;
  callLog.runScan = 0;
  callLog.callDeepSeek = 0;
  callLog.insertReport = 0;
});

describe("processScanJob — abandoned when the scan row is gone", () => {
  it("does no scanning at all when the row was deleted while the job sat in the queue", async () => {
    // Step 1's update matches nothing: the account was deleted before a worker
    // slot freed up. This is the case that dominated the measurement — 12 of the
    // 20 queued behind the 8-job concurrency cap were in exactly this state.
    updateReturns.push([]);

    const { processScanJob } = await load();
    await expect(processScanJob(job)).resolves.toBeUndefined();

    expect(callLog.runScan).toBe(0);
    expect(callLog.callDeepSeek).toBe(0);
    expect(callLog.insertReport).toBe(0);
  });

  it("refuses to pay for an AI call when the row disappears mid-scan", async () => {
    // Step 1 finds the row, so the scan runs; by step 3 the owner has deleted
    // the account. The scan is already spent, but the DeepSeek call is not.
    updateReturns.push([{ id: "scan-1" }]); // step 1: still there
    updateReturns.push([]);                 // step 3: gone

    const { processScanJob } = await load();
    await expect(processScanJob(job)).resolves.toBeUndefined();

    expect(callLog.runScan).toBe(1);
    expect(callLog.callDeepSeek).toBe(0);
    expect(callLog.insertReport).toBe(0);
  });

  it("runs the whole job when the row is present throughout", async () => {
    // The guards must not abandon a healthy scan: same path, nothing deleted.
    updateReturns.push([{ id: "scan-1" }]); // step 1
    updateReturns.push([{ id: "scan-1" }]); // step 3

    const { processScanJob } = await load();
    await processScanJob(job);

    expect(callLog.runScan).toBe(1);
    expect(callLog.callDeepSeek).toBe(1);
    expect(callLog.insertReport).toBe(1);
  });
});
