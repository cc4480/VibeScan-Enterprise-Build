import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The report-ready email links through a share token so it resolves WITHOUT a
 * session. These pin the properties that make that safe and make it work.
 *
 * The bug this closes: the email linked at /report/:id, which requires being
 * signed in as the report's owner. Opened on a phone — logged out (401) or
 * signed into a different account (404) — it rendered a bare "Failed to load
 * report", so the person the report was mailed to could not read it. Seen live:
 * one report answered 200 on the device that ran the scan and 404 on the
 * owner's own phone.
 */

const inserted: Array<Record<string, unknown>> = [];

vi.mock("@workspace/db", () => ({
  reportSharesTable: {},
  db: {
    insert: () => ({
      values: (v: Record<string, unknown>) => ({
        returning: () => {
          const row = { id: `share_${inserted.length + 1}`, createdAt: new Date(), ...v };
          inserted.push(row);
          return Promise.resolve([row]);
        },
      }),
    }),
  },
}));

const { createReportShare, computeShareExpiry, shareUrl } = await import("./reportShare");

beforeEach(() => {
  inserted.length = 0;
});

describe("createReportShare", () => {
  it("scopes the share to the report AND the owner it was passed", async () => {
    await createReportShare("report_1", "user_42");
    expect(inserted[0]).toMatchObject({ reportId: "report_1", userId: "user_42" });
  });

  // The token is the only thing standing between a URL and one report's
  // contents, so it must be unguessable — 32 bytes of CSPRNG as 64 hex chars.
  it("mints a 64-hex-character token", async () => {
    const share = await createReportShare("report_1", "user_42");
    expect(share.token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("never repeats a token across calls", async () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 50; i++) tokens.add((await createReportShare("r", "u")).token);
    expect(tokens.size).toBe(50);
  });

  it("defaults to no expiry so an emailed report link does not rot", async () => {
    const share = await createReportShare("report_1", "user_42");
    expect(share.expiresAt).toBeNull();
  });

  it("honours an explicit expiry window", async () => {
    const share = await createReportShare("report_1", "user_42", "7d");
    expect(share.expiresAt).toBeInstanceOf(Date);
    const days = (share.expiresAt!.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThan(7.1);
  });
});

describe("computeShareExpiry", () => {
  it("returns null for never, a date for the bounded windows", () => {
    expect(computeShareExpiry("never")).toBeNull();
    expect(computeShareExpiry("7d")).toBeInstanceOf(Date);
    expect(computeShareExpiry("30d")).toBeInstanceOf(Date);
  });
});

describe("shareUrl", () => {
  // Must be /share/:token — the route App.tsx actually serves and the link the
  // in-app share dialog hands users. /s/:token serves nothing (shared-report.tsx
  // had it as its canonical URL, which 404s), and /report/:id is the
  // session-gated path whose 401/404 is the whole bug being fixed.
  it("builds the public /share/ path, not /s/ and not the gated /report/", () => {
    expect(shareUrl("https://secscan.us", "abc123")).toBe("https://secscan.us/share/abc123");
    expect(shareUrl("https://secscan.us", "abc123")).not.toContain("/report/");
  });

  it("does not double the slash when the origin has a trailing one", () => {
    expect(shareUrl("https://secscan.us/", "abc123")).toBe("https://secscan.us/share/abc123");
  });
});
