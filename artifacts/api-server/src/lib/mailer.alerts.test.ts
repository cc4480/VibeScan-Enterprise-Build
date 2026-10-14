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

/**
 * The email an address that already has an account gets when someone signs up
 * with it. POST /account/register answers new and existing addresses alike, so
 * this message is the only place the owner learns what happened.
 *
 * It must fail like the sign-in code does (throw), or a send failure would make
 * the two paths answer differently and bring the oracle back.
 */
describe("sendSignupExistingAccountEmail", () => {
  async function stubSuppressed(suppressed: boolean) {
    const supp = await import("./emailSuppression.js");
    vi.spyOn(supp, "isSuppressed").mockResolvedValue(suppressed);
    vi.spyOn(supp, "healBounceSuppression").mockResolvedValue(undefined);
  }

  beforeEach(() => {
    process.env.RESEND_API_KEY = "re_test_key";
    process.env.FROM_EMAIL = "SecScan <reports@secscan.us>";
    process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
  });

  it("tells the owner they already have an account, with sign-in and reset links and no code", async () => {
    await stubSuppressed(false);
    const { sendSignupExistingAccountEmail } = await import("./mailer.js");
    const { APP_ORIGIN } = await import("./appOrigin.js");

    await sendSignupExistingAccountEmail("owner@example.com");

    expect(fetch).toHaveBeenCalledTimes(1);
    const [, init] = vi.mocked(fetch).mock.calls[0]!;
    const sent = JSON.parse((init as RequestInit).body as string);
    // Account mail leaves from the account sender, like the code it replaces.
    expect(sent.from).toBe("SecScan <codes@mail.secscan.us>");
    expect(sent.to).toEqual(["owner@example.com"]);
    expect(sent.subject).toMatch(/already have/i);
    for (const part of [sent.html, sent.text]) {
      expect(part).toContain(`${APP_ORIGIN}/sign-in`);
      expect(part).toContain(`${APP_ORIGIN}/forgot-password`);
      expect(part).toMatch(/already/i);
      expect(part).not.toMatch(/\b\d{3} ?\d{3}\b/);
    }
  });

  it("throws when the provider refuses, so the route can answer 502 as it does for a code", async () => {
    await stubSuppressed(false);
    vi.mocked(fetch).mockResolvedValue(new Response("boom", { status: 500 }));
    const { sendSignupExistingAccountEmail } = await import("./mailer.js");

    await expect(sendSignupExistingAccountEmail("owner@example.com")).rejects.toThrow(/Resend API 500/);
  });

  it("throws when no mail provider is configured", async () => {
    await stubSuppressed(false);
    delete process.env.RESEND_API_KEY;
    const { sendSignupExistingAccountEmail } = await import("./mailer.js");

    await expect(sendSignupExistingAccountEmail("owner@example.com")).rejects.toThrow(/RESEND_API_KEY/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("throws, without sending, for a suppressed address, as sendLoginCode does", async () => {
    await stubSuppressed(true);
    const { sendSignupExistingAccountEmail, sendLoginCode } = await import("./mailer.js");

    await expect(sendSignupExistingAccountEmail("gone@example.com")).rejects.toThrow(/suppression/);
    await expect(sendLoginCode("gone@example.com", "123456", 10)).rejects.toThrow(/suppression/);
    expect(fetch).not.toHaveBeenCalled();
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
