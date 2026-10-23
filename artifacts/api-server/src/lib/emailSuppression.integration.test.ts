/**
 * Which delivery events stop which mail, against a REAL Postgres (BILLING_TEST_DATABASE_URL).
 *
 * Every mistake in this table is silent: nobody notices that a bounce was ignored until reputation has already
 * slipped, and nobody notices that a complaint suppressed the wrong thing until someone cannot log in. So the
 * decisions are pinned individually, especially the two that are easy to get backwards: soft bounces must NOT
 * suppress, and a complaint must NOT stop account mail.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "./realDb.testkit";

useRealDb();

describe("suppressionForEvent", () => {
  // Imported after useRealDb(), so the db module this pulls in is built against the real URL.
  let suppressionForEvent: typeof import("./emailSuppression").suppressionForEvent;
  beforeAll(async () => {
    ({ suppressionForEvent } = await import("./emailSuppression"));
  });

  it("suppresses ALL mail after a hard bounce: the address does not exist", () => {
    expect(
      suppressionForEvent("email.bounced", { to: "gone@example.com", bounce: { type: "Permanent", subType: "NoEmail" } }),
    ).toMatchObject({ email: "gone@example.com", scope: "all", reason: "hard_bounce" });
  });

  // THE one to get right. A soft bounce is a full mailbox or a transient server problem; it clears by itself.
  // Suppressing on one would quietly cut off a real user whose inbox was briefly over quota.
  it("does NOT suppress on a soft bounce", () => {
    expect(
      suppressionForEvent("email.bounced", { to: "full@example.com", bounce: { type: "Transient", subType: "MailboxFull" } }),
    ).toBeNull();
  });

  it("suppresses only BULK mail after a complaint", () => {
    expect(suppressionForEvent("email.complained", { to: "cross@example.com" })).toMatchObject({ scope: "bulk", reason: "complaint" });
  });

  it("ignores events that say nothing about deliverability", () => {
    for (const t of ["email.sent", "email.delivered", "email.opened", "email.clicked", "email.delivery_delayed"]) {
      expect(suppressionForEvent(t, { to: "a@b.co" })).toBeNull();
    }
  });

  it("reads the recipient whether Resend sends a string or an array", () => {
    expect(suppressionForEvent("email.complained", { to: ["arr@example.com"] })?.email).toBe("arr@example.com");
    expect(suppressionForEvent("email.complained", { to: "str@example.com" })?.email).toBe("str@example.com");
  });

  it("returns null rather than throwing on a payload with no recipient", () => {
    expect(suppressionForEvent("email.bounced", {})).toBeNull();
    expect(suppressionForEvent("email.bounced", { to: [] })).toBeNull();
  });
});

dbSuiteOf(describe)("the suppression list (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let mod: typeof import("./emailSuppression");
  let eq: typeof import("drizzle-orm").eq;
  let sql: typeof import("drizzle-orm").sql;
  const addresses: string[] = [];
  /** A fresh address per test: the table is keyed by address and shared with every other suite. */
  const addr = (tag: string) => {
    const a = uniqueEmail(tag);
    addresses.push(a);
    return a;
  };
  const rowsFor = async (email: string) => dbMod.db.select().from(dbMod.emailSuppressionsTable).where(eq(dbMod.emailSuppressionsTable.email, email));

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq, sql } = await import("drizzle-orm"));
    mod = await import("./emailSuppression");
    // Heal a database left half-way through the fail-open test below by an interrupted run.
    await dbMod.db.execute(sql`DO $$ BEGIN
      IF to_regclass('public.email_suppressions') IS NULL AND to_regclass('public.email_suppressions_offline') IS NOT NULL THEN
        ALTER TABLE email_suppressions_offline RENAME TO email_suppressions;
      END IF; END $$`);
  }, 60_000);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (addresses.length) await dbMod.db.delete(dbMod.emailSuppressionsTable).where(inArray(dbMod.emailSuppressionsTable.email, addresses));
    await dbMod?.pool?.end?.();
  });

  describe("isSuppressed", () => {
    it("blocks everything for a hard-bounced address", async () => {
      const a = addr("gone");
      await mod.suppressEmail(a, "all", "hard_bounce");
      expect(await mod.isSuppressed(a, "bulk")).toBe(true);
      expect(await mod.isSuppressed(a, "account")).toBe(true);
    });

    // The decision that keeps a newsletter complaint from locking someone out of their own account.
    it("blocks bulk but NOT account mail for someone who complained", async () => {
      const a = addr("cross");
      await mod.suppressEmail(a, "bulk", "complaint");
      expect(await mod.isSuppressed(a, "bulk")).toBe(true);
      expect(await mod.isSuppressed(a, "account")).toBe(false);
    });

    it("does not block an address that was never suppressed", async () => {
      expect(await mod.isSuppressed(addr("fine"), "bulk")).toBe(false);
    });

    it("matches regardless of case or surrounding whitespace", async () => {
      const a = addr("mixed");
      await mod.suppressEmail(`  ${a.toUpperCase()} `, "all", "hard_bounce");
      expect(await mod.isSuppressed(a, "account")).toBe(true);
    });

    // Fails OPEN on purpose. A database blip that silently stopped every sign-in code in the system would be far
    // worse than one extra message to an address that bounced. The failure here is real: the table is taken away
    // (a half-migrated deploy), so the lookup genuinely errors, and it is put back straight afterwards.
    it("sends anyway if the lookup throws, rather than silencing all mail", async () => {
      const a = addr("failopen");
      await mod.suppressEmail(a, "all", "hard_bounce");
      expect(await mod.isSuppressed(a, "account")).toBe(true);
      await dbMod.db.execute(sql`ALTER TABLE email_suppressions RENAME TO email_suppressions_offline`);
      try {
        expect(await mod.isSuppressed(a, "account")).toBe(false);
      } finally {
        await dbMod.db.execute(sql`ALTER TABLE email_suppressions_offline RENAME TO email_suppressions`);
      }
      expect(await mod.isSuppressed(a, "account")).toBe(true);
    });
  });

  describe("suppressEmail", () => {
    it("upserts rather than accumulating rows for a repeated webhook", async () => {
      const a = addr("dup");
      await mod.suppressEmail(a, "bulk", "complaint");
      await mod.suppressEmail(a, "bulk", "complaint");
      expect(await rowsFor(a)).toHaveLength(1);
    });

    // Someone who complained AND whose mailbox was then deleted is both; the stricter rule is the true one.
    // Widening back to bulk-only would resume mailing an address that does not exist.
    it("never downgrades an existing 'all' back to 'bulk'", async () => {
      const a = addr("both");
      await mod.suppressEmail(a, "all", "hard_bounce");
      await mod.suppressEmail(a, "bulk", "complaint");
      expect(await mod.isSuppressed(a, "account")).toBe(true);
      expect((await rowsFor(a))[0]!.scope).toBe("all");
    });

    it("does upgrade a 'bulk' to 'all' when the address later hard-bounces", async () => {
      const a = addr("up");
      await mod.suppressEmail(a, "bulk", "complaint");
      await mod.suppressEmail(a, "all", "hard_bounce");
      expect(await mod.isSuppressed(a, "account")).toBe(true);
    });

    it("ignores an empty address instead of writing a blank row", async () => {
      await mod.suppressEmail("   ", "all", "hard_bounce");
      expect(await rowsFor("")).toHaveLength(0);
    });
  });

  describe("unsuppressEmail", () => {
    it("lifts a suppression so the address receives mail again", async () => {
      const a = addr("fixed");
      await mod.suppressEmail(a, "all", "hard_bounce");
      await mod.unsuppressEmail(a);
      expect(await mod.isSuppressed(a, "account")).toBe(false);
    });
  });

  describe("healBounceSuppression", () => {
    it("lifts a hard-bounce suppression", async () => {
      const a = addr("retry");
      await mod.suppressEmail(a, "all", "hard_bounce");
      await mod.healBounceSuppression(a);
      expect(await mod.isSuppressed(a, "account")).toBe(false);
    });

    // A complaint is someone saying stop, not a delivery failure. Asking for a password reset must never be read
    // as consent to resume mailing them.
    it("does NOT lift a complaint-based suppression", async () => {
      const a = addr("cross2");
      await mod.suppressEmail(a, "bulk", "complaint");
      await mod.healBounceSuppression(a);
      expect(await mod.isSuppressed(a, "bulk")).toBe(true);
    });

    it("does nothing for an address that was never suppressed", async () => {
      const a = addr("fine2");
      await mod.healBounceSuppression(a);
      expect(await rowsFor(a)).toHaveLength(0);
    });
  });
});
