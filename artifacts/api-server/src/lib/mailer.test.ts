import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
  process.env = { ...ORIGINAL_ENV };
});

describe("addToMarketingAudience", () => {
  it("skips silently when RESEND_AUDIENCE_API_KEY or RESEND_AUDIENCE_ID is unset", async () => {
    delete process.env.RESEND_AUDIENCE_API_KEY;
    delete process.env.RESEND_AUDIENCE_ID;
    const { addToMarketingAudience } = await import("./mailer.js");

    await addToMarketingAudience("user@example.com");

    expect(fetch).not.toHaveBeenCalled();
  });

  it("posts the contact to the configured audience when both vars are set", async () => {
    process.env.RESEND_AUDIENCE_API_KEY = "re_test_key";
    process.env.RESEND_AUDIENCE_ID = "aud_123";
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    const { addToMarketingAudience } = await import("./mailer.js");

    await addToMarketingAudience("user@example.com", "Alex");

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(String(url)).toBe("https://api.resend.com/audiences/aud_123/contacts");
    expect((init as RequestInit).headers).toMatchObject({ Authorization: "Bearer re_test_key" });
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toMatchObject({ email: "user@example.com", first_name: "Alex", unsubscribed: false });
  });

  it("does not throw when the Resend API call fails", async () => {
    process.env.RESEND_AUDIENCE_API_KEY = "re_test_key";
    process.env.RESEND_AUDIENCE_ID = "aud_123";
    vi.mocked(fetch).mockResolvedValue(new Response("boom", { status: 500 }));
    const { addToMarketingAudience } = await import("./mailer.js");

    await expect(addToMarketingAudience("user@example.com")).resolves.toBeUndefined();
  });
});

describe("sendWelcomeEmail", () => {
  it("skips silently when RESEND_API_KEY is unset", async () => {
    delete process.env.RESEND_API_KEY;
    const { sendWelcomeEmail } = await import("./mailer.js");

    await sendWelcomeEmail("user@example.com");

    expect(fetch).not.toHaveBeenCalled();
  });

  it("sends via the standard Resend emails endpoint when RESEND_API_KEY is set", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    const { sendWelcomeEmail } = await import("./mailer.js");

    await sendWelcomeEmail("user@example.com", "Alex");

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(String(url)).toBe("https://api.resend.com/emails");
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.to).toEqual(["user@example.com"]);
    expect(body.html).toContain("Alex");
  });
});

/**
 * Account mail and bulk mail must be able to leave from different senders.
 *
 * Every message this service sends currently goes out from one address, so a
 * spam complaint about a CVE alert is a complaint against the address that
 * delivers sign-in codes — and a sign-in code in Junk is indistinguishable
 * from a broken login. AUTH_FROM_EMAIL is the seam that lets account mail be
 * moved to its own verified subdomain, where its reputation is its own.
 *
 * The realistic regression is not someone deleting this: it is someone adding
 * a new account sender and routing it through the bulk `from` without
 * noticing, which has no symptom until deliverability quietly degrades. These
 * assert the split by its effect on the actual Resend payload.
 */
describe("account mail vs bulk mail sender", () => {
  const REPORT_OPTS = {
    toEmail: "user@example.com",
    targetUrl: "https://example.com",
    grade: "B",
    riskScore: 22,
    totalVulns: 7,
    reportUrl: "https://secscan.us/report/abc",
    tier: "deep",
  };

  /** The `from` on the single Resend call the sender under test made. */
  function sentFrom(): string {
    expect(fetch).toHaveBeenCalledTimes(1);
    const [, init] = vi.mocked(fetch).mock.calls[0]!;
    return JSON.parse((init as RequestInit).body as string).from;
  }

  beforeEach(() => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.FROM_EMAIL = "SecScan <reports@secscan.us>";
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
  });

  it("sends the sign-in code from the account sender", async () => {
    process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
    const { sendLoginCode } = await import("./mailer.js");

    await sendLoginCode("user@example.com", "123456", 10);

    expect(sentFrom()).toBe("SecScan <codes@mail.secscan.us>");
  });

  it("sends a password reset from the account sender", async () => {
    // Routed through the shared account helper rather than its own request,
    // so this also covers email verification and purchase receipts.
    process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
    const { sendPasswordReset } = await import("./mailer.js");

    await sendPasswordReset("user@example.com", "https://secscan.us/reset?t=x");

    expect(sentFrom()).toBe("SecScan <codes@mail.secscan.us>");
  });

  it("keeps bulk mail on the notification sender, so the two reputations stay apart", async () => {
    // The assertion that gives the split its point: with an account sender
    // configured, a notification must NOT inherit it.
    process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
    const { sendReportReadyEmail } = await import("./mailer.js");

    await sendReportReadyEmail(REPORT_OPTS);

    expect(sentFrom()).toBe("SecScan <reports@secscan.us>");
  });

  it("falls back to the notification sender when no account sender is configured", async () => {
    // The deployed state today: AUTH_FROM_EMAIL unset must change nothing.
    delete process.env.AUTH_FROM_EMAIL;
    const { sendLoginCode } = await import("./mailer.js");

    await sendLoginCode("user@example.com", "123456", 10);

    expect(sentFrom()).toBe("SecScan <reports@secscan.us>");
  });
});

/**
 * Does turning a preference off actually stop the email?
 *
 * The settings screen animates a toggle and the API stores a column, but
 * neither proves a send is prevented. These call the real senders with the
 * preference lookup stubbed, and assert on whether Resend was reached at all —
 * the same shape as the webhook tests, for the half that had no coverage.
 */
describe("alert email honours notification preferences", () => {
  const CERT_OPTS = {
    toEmail: "user@example.com",
    userId: "user-1",
    targetUrl: "https://example.com",
    daysRemaining: 7,
    expiryDate: new Date("2026-10-01T00:00:00.000Z"),
    dashboardUrl: "https://secscan.us/monitor",
  };

  async function withPrefs(over: Partial<Awaited<ReturnType<typeof import("./notificationPrefs").notificationPrefs>>>) {
    const mod = await import("./notificationPrefs.js");
    vi.spyOn(mod, "notificationPrefs").mockResolvedValue({ ...mod.defaultPrefs(), ...over });
    const supp = await import("./emailSuppression.js");
    vi.spyOn(supp, "isSuppressed").mockResolvedValue(false);
  }

  beforeEach(() => {
    process.env.RESEND_API_KEY = "re_test_key";
    // Alert mail carries a signed List-Unsubscribe header (RFC 8058), and
    // signing throws without this. Without it every assertion below passes
    // for the wrong reason: fetch is never reached because the sender crashed,
    // not because a preference blocked it — which is exactly what the control
    // test at the top of this block exists to expose.
    process.env.ENCRYPTION_KEY = "0".repeat(64);
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
  });

  it("sends a cert-expiry email when nothing is turned off", async () => {
    // The control. Without it every refusal below could pass while proving
    // only that the mailer is broken.
    await withPrefs({});
    const { sendCertExpiryEmail } = await import("./mailer.js");

    await sendCertExpiryEmail(CERT_OPTS);

    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("does NOT send when that alert kind is turned off", async () => {
    await withPrefs({ optedOutKinds: new Set(["cert_expiry"] as const) });
    const { sendCertExpiryEmail } = await import("./mailer.js");

    await sendCertExpiryEmail(CERT_OPTS);

    expect(fetch).not.toHaveBeenCalled();
  });

  it("does NOT send when the master email switch is off", async () => {
    await withPrefs({ emailOptedOut: true });
    const { sendCertExpiryEmail } = await import("./mailer.js");

    await sendCertExpiryEmail(CERT_OPTS);

    expect(fetch).not.toHaveBeenCalled();
  });

  it("still sends cert expiry at the highest severity floor", async () => {
    // Cert expiry carries no severity. If the floor applied to it, raising
    // the threshold would silently switch off expiry warnings — the single
    // alert people least want to lose.
    await withPrefs({ minSeverity: "critical" });
    const { sendCertExpiryEmail } = await import("./mailer.js");

    await sendCertExpiryEmail(CERT_OPTS);

    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
