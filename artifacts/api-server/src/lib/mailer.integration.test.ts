/**
 * The mailer, run for real: the real senders build the real requests and send them over HTTP to a local endpoint
 * that records them (lib/mailSink.testkit.ts), with real suppression and notification-preference lookups against a
 * REAL Postgres (BILLING_TEST_DATABASE_URL). Only the provider's end of the wire is a stand-in.
 *
 * The mailer reads its sender addresses and endpoint when it loads, so each test imports it afresh.
 */
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "./realDb.testkit";
import { startMailSink, type MailSink } from "./mailSink.testkit";

useRealDb();
const ORIGINAL_ENV = { ...process.env };

dbSuiteOf(describe)("mailer (real senders, local mail endpoint, real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let sink: MailSink;
  let base: string;
  const users: string[] = [];
  const addresses: string[] = [];

  beforeAll(async () => {
    dbMod = await openDb();
    sink = await startMailSink();
    base = process.env["RESEND_BASE_URL"]!;
  }, 60_000);

  beforeEach(() => {
    vi.resetModules();
    sink.clear();
    process.env = { ...ORIGINAL_ENV, RESEND_BASE_URL: base };
    delete process.env.RESEND_API_KEY;
    delete process.env.RESEND_AUDIENCE_API_KEY;
    delete process.env.RESEND_AUDIENCE_ID;
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  afterAll(async () => {
    await sink?.stop();
    const { inArray } = await import("drizzle-orm");
    if (users.length) await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    if (addresses.length) await dbMod.db.delete(dbMod.emailSuppressionsTable).where(inArray(dbMod.emailSuppressionsTable.email, addresses));
    await dbMod?.pool?.end?.();
  });

  const newAddress = (tag: string) => {
    const a = uniqueEmail(tag);
    addresses.push(a);
    return a;
  };

  describe("addToMarketingAudience", () => {
    it("skips silently when RESEND_AUDIENCE_API_KEY or RESEND_AUDIENCE_ID is unset", async () => {
      const { addToMarketingAudience } = await import("./mailer.js");
      await addToMarketingAudience("user@example.com");
      expect(sink.mail).toHaveLength(0);
    });

    it("posts the contact to the configured audience when both vars are set", async () => {
      process.env.RESEND_AUDIENCE_API_KEY = "re_test_key";
      process.env.RESEND_AUDIENCE_ID = "aud_123";
      const { addToMarketingAudience } = await import("./mailer.js");

      await addToMarketingAudience("user@example.com", "Alex");

      expect(sink.mail).toHaveLength(1);
      const m = sink.mail[0]!;
      expect(m.path).toBe("/audiences/aud_123/contacts");
      expect(m.authorization).toBe("Bearer re_test_key");
      expect(m.body).toMatchObject({ email: "user@example.com", first_name: "Alex", unsubscribed: false });
    });

    it("does not throw when the Resend API call fails", async () => {
      process.env.RESEND_AUDIENCE_API_KEY = "re_test_key";
      process.env.RESEND_AUDIENCE_ID = "aud_123";
      sink.respondWith(500);
      const { addToMarketingAudience } = await import("./mailer.js");
      await expect(addToMarketingAudience("user@example.com")).resolves.toBeUndefined();
    });
  });

  describe("sendWelcomeEmail", () => {
    it("skips silently when RESEND_API_KEY is unset", async () => {
      const { sendWelcomeEmail } = await import("./mailer.js");
      await sendWelcomeEmail("user@example.com");
      expect(sink.mail).toHaveLength(0);
    });

    it("sends via the standard emails endpoint when RESEND_API_KEY is set", async () => {
      process.env.RESEND_API_KEY = "re_test_key";
      const { sendWelcomeEmail } = await import("./mailer.js");

      await sendWelcomeEmail("user@example.com", "Alex");

      expect(sink.mail).toHaveLength(1);
      expect(sink.mail[0]!.path).toBe("/emails");
      expect(sink.mail[0]!.to).toEqual(["user@example.com"]);
      expect(sink.mail[0]!.html).toContain("Alex");
    });
  });

  /**
   * Account mail and bulk mail must be able to leave from different senders.
   *
   * Every message this service sends currently goes out from one address, so a spam complaint about a CVE alert is a
   * complaint against the address that delivers sign-in codes, and a sign-in code in Junk is indistinguishable from a
   * broken login. AUTH_FROM_EMAIL is the seam that lets account mail be moved to its own verified subdomain.
   *
   * The realistic regression is someone adding a new account sender and routing it through the bulk `from` without
   * noticing. These assert the split by its effect on the payload that actually arrives.
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

    /** The `from` on the single message the sender under test sent. */
    function sentFrom(): string | undefined {
      expect(sink.mail).toHaveLength(1);
      return sink.mail[0]!.from;
    }

    beforeEach(() => {
      process.env.RESEND_API_KEY = "re_test_key";
      process.env.FROM_EMAIL = "SecScan <reports@secscan.us>";
    });

    it("sends the sign-in code from the account sender", async () => {
      process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
      const { sendLoginCode } = await import("./mailer.js");
      await sendLoginCode(newAddress("code"), "123456", 10);
      expect(sentFrom()).toBe("SecScan <codes@mail.secscan.us>");
    });

    it("sends a password reset from the account sender", async () => {
      // Routed through the shared account helper rather than its own request, so this also covers email
      // verification and purchase receipts.
      process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
      const { sendPasswordReset } = await import("./mailer.js");
      await sendPasswordReset(newAddress("reset"), "https://secscan.us/reset?t=x");
      expect(sentFrom()).toBe("SecScan <codes@mail.secscan.us>");
    });

    it("keeps bulk mail on the notification sender, so the two reputations stay apart", async () => {
      // The assertion that gives the split its point: with an account sender configured, a notification must NOT inherit it.
      process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
      const { sendReportReadyEmail } = await import("./mailer.js");
      await sendReportReadyEmail({ ...REPORT_OPTS, toEmail: newAddress("report") });
      expect(sentFrom()).toBe("SecScan <reports@secscan.us>");
    });

    it("falls back to the notification sender when no account sender is configured", async () => {
      // The deployed state today: AUTH_FROM_EMAIL unset must change nothing.
      delete process.env.AUTH_FROM_EMAIL;
      const { sendLoginCode } = await import("./mailer.js");
      await sendLoginCode(newAddress("fallback"), "123456", 10);
      expect(sentFrom()).toBe("SecScan <reports@secscan.us>");
    });

    describe("the report-ready email says how much was tested", () => {
      const sentHtml = () => {
        expect(sink.mail).toHaveLength(1);
        return sink.mail[0]!.html!;
      };
      const send = async (coverage?: { ran: number; skipped: number; failed: number; total: number }) => {
        const { sendReportReadyEmail } = await import("./mailer.js");
        await sendReportReadyEmail({ ...REPORT_OPTS, toEmail: newAddress("cov"), ...(coverage ? { coverage } : {}) });
      };

      it("puts the test count and the not-tested warning next to a grade", async () => {
        await send({ ran: 37, skipped: 2, failed: 0, total: 39 });
        const html = sentHtml();
        expect(html).toContain("Tests run");
        expect(html).toContain("37<span");
        expect(html).toContain("/39");
        expect(html).toContain("2 tests did not run");
        expect(html).toContain("says nothing about those areas");
      });

      it("counts failed tests as not tested too", async () => {
        await send({ ran: 36, skipped: 1, failed: 2, total: 39 });
        expect(sentHtml()).toContain("3 tests did not run");
      });

      it("does not raise a warning when every test ran", async () => {
        await send({ ran: 39, skipped: 0, failed: 0, total: 39 });
        const html = sentHtml();
        expect(html).toContain("39<span");
        expect(html).not.toContain("did not run");
      });

      it("claims nothing when no record exists", async () => {
        await send();
        expect(sentHtml()).not.toContain("Tests run");
      });
    });
  });

  /**
   * The email an address that already has an account gets when someone signs up with it. POST /account/register
   * answers new and existing addresses alike, so this message is the only place the owner learns what happened.
   *
   * It must fail like the sign-in code does (throw), or a send failure would make the two paths answer differently
   * and bring the oracle back.
   */
  describe("sendSignupExistingAccountEmail", () => {
    beforeEach(() => {
      process.env.RESEND_API_KEY = "re_test_key";
      process.env.FROM_EMAIL = "SecScan <reports@secscan.us>";
      process.env.AUTH_FROM_EMAIL = "SecScan <codes@mail.secscan.us>";
    });

    it("tells the owner they already have an account, with sign-in and reset links and no code", async () => {
      const { sendSignupExistingAccountEmail } = await import("./mailer.js");
      const { APP_ORIGIN } = await import("./appOrigin.js");
      const owner = newAddress("owner");

      await sendSignupExistingAccountEmail(owner);

      expect(sink.mail).toHaveLength(1);
      const sent = sink.mail[0]!;
      // Account mail leaves from the account sender, like the code it replaces.
      expect(sent.from).toBe("SecScan <codes@mail.secscan.us>");
      expect(sent.to).toEqual([owner]);
      expect(sent.subject).toMatch(/already have/i);
      for (const part of [sent.html!, sent.text!]) {
        expect(part).toContain(`${APP_ORIGIN}/sign-in`);
        expect(part).toContain(`${APP_ORIGIN}/forgot-password`);
        expect(part).toMatch(/already/i);
        expect(part).not.toMatch(/\b\d{3} ?\d{3}\b/);
      }
    });

    it("throws when the provider refuses, so the route can answer 502 as it does for a code", async () => {
      sink.respondWith(500);
      const { sendSignupExistingAccountEmail } = await import("./mailer.js");
      await expect(sendSignupExistingAccountEmail(newAddress("refused"))).rejects.toThrow(/Resend API 500/);
    });

    it("throws when no mail provider is configured", async () => {
      delete process.env.RESEND_API_KEY;
      const { sendSignupExistingAccountEmail } = await import("./mailer.js");
      await expect(sendSignupExistingAccountEmail(newAddress("nokey"))).rejects.toThrow(/RESEND_API_KEY/);
      expect(sink.mail).toHaveLength(0);
    });

    it("gives a stale hard bounce one more try before refusing, and sends", async () => {
      // Asking for a sign-in code or signing up is a request that mail reach the address now, so a hard bounce from
      // weeks ago is lifted first (healBounceSuppression). Without this one bounce locks a real account out for good.
      const stale = newAddress("stale");
      const { suppressEmail, isSuppressed } = await import("./emailSuppression.js");
      await suppressEmail(stale, "all", "hard_bounce");
      const { sendSignupExistingAccountEmail } = await import("./mailer.js");
      await sendSignupExistingAccountEmail(stale);
      expect(sink.mail).toHaveLength(1);
      expect(await isSuppressed(stale, "account")).toBe(false);
    });

    it("throws, without sending, for a suppressed address, as sendLoginCode does", async () => {
      // A manual block is not a delivery failure, so it is not lifted the way a stale bounce is.
      const gone = newAddress("gone");
      const { suppressEmail } = await import("./emailSuppression.js");
      await suppressEmail(gone, "all", "manual");
      const { sendSignupExistingAccountEmail, sendLoginCode } = await import("./mailer.js");

      await expect(sendSignupExistingAccountEmail(gone)).rejects.toThrow(/suppression/);
      await expect(sendLoginCode(gone, "123456", 10)).rejects.toThrow(/suppression/);
      expect(sink.mail).toHaveLength(0);
    });
  });

  /**
   * Does turning a preference off actually stop the email?
   *
   * The settings screen animates a toggle and the API stores a column, but neither proves a send is prevented. These
   * call the real sender for a real user whose preferences are really stored, and assert whether a message reached the
   * provider at all.
   */
  describe("alert email honours notification preferences", () => {
    const CERT_OPTS = (userId: string) => ({
      toEmail: uniqueEmail("alert"),
      userId,
      targetUrl: "https://example.com",
      daysRemaining: 7,
      expiryDate: new Date("2026-10-01T00:00:00.000Z"),
      dashboardUrl: "https://secscan.us/monitor",
    });

    async function userWith(prefs: Partial<typeof dbMod.usersTable.$inferInsert>) {
      const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email: uniqueEmail("prefs"), ...prefs }).returning({ id: dbMod.usersTable.id });
      users.push(u!.id);
      return u!.id;
    }

    beforeEach(() => {
      process.env.RESEND_API_KEY = "re_test_key";
      // Alert mail carries a signed List-Unsubscribe header (RFC 8058), and signing throws without this. Without it every
      // refusal below would pass for the wrong reason: nothing sent because the sender crashed, not because a preference
      // blocked it. That is exactly what the control test at the top of this block exists to expose.
      process.env.ENCRYPTION_KEY = "0".repeat(64);
    });

    it("sends a cert-expiry email when nothing is turned off", async () => {
      // The control. Without it every refusal below could pass while proving only that the mailer is broken.
      const id = await userWith({});
      const { sendCertExpiryEmail } = await import("./mailer.js");
      await sendCertExpiryEmail(CERT_OPTS(id));
      expect(sink.mail).toHaveLength(1);
    });

    it("does NOT send when that alert kind is turned off", async () => {
      const id = await userWith({ notifyCertExpiryOptedOut: true });
      const { sendCertExpiryEmail } = await import("./mailer.js");
      await sendCertExpiryEmail(CERT_OPTS(id));
      expect(sink.mail).toHaveLength(0);
    });

    it("does NOT send when the master email switch is off", async () => {
      const id = await userWith({ alertEmailsOptedOut: true });
      const { sendCertExpiryEmail } = await import("./mailer.js");
      await sendCertExpiryEmail(CERT_OPTS(id));
      expect(sink.mail).toHaveLength(0);
    });

    it("still sends cert expiry at the highest severity floor", async () => {
      // Cert expiry carries no severity. If the floor applied to it, raising the threshold would silently switch off
      // expiry warnings: the single alert people least want to lose.
      const id = await userWith({ notifyMinSeverity: "critical" });
      const { sendCertExpiryEmail } = await import("./mailer.js");
      await sendCertExpiryEmail(CERT_OPTS(id));
      expect(sink.mail).toHaveLength(1);
    });

    it("does NOT send to an address on the suppression list", async () => {
      const id = await userWith({});
      const opts = CERT_OPTS(id);
      addresses.push(opts.toEmail);
      const { suppressEmail } = await import("./emailSuppression.js");
      await suppressEmail(opts.toEmail, "bulk", "complaint");
      const { sendCertExpiryEmail } = await import("./mailer.js");
      await sendCertExpiryEmail(opts);
      expect(sink.mail).toHaveLength(0);
    });
  });
});
