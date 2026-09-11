import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Which delivery events stop which mail.
 *
 * Every mistake in this table is silent — nobody notices that a bounce was
 * ignored until reputation has already slipped, and nobody notices that a
 * complaint suppressed the wrong thing until someone cannot log in. So the
 * decisions are pinned individually, especially the two that are easy to get
 * backwards: soft bounces must NOT suppress, and a complaint must NOT stop
 * account mail.
 */

interface Row {
  email: string;
  scope: "all" | "bulk";
  reason: string;
  detail: string | null;
  updatedAt?: Date;
}

const rows: Row[] = [];
let shouldThrow = false;

vi.mock("drizzle-orm", () => ({ eq: (col: string, val: unknown) => ({ col, val }) }));

vi.mock("@workspace/db", () => ({
  emailSuppressionsTable: { email: "email" },
  db: {
    select: () => ({
      from: () => ({
        where: (p: { val: unknown }) => {
          if (shouldThrow) return Promise.reject(new Error("database is down"));
          return Promise.resolve(rows.filter((r) => r.email === p.val));
        },
      }),
    }),
    insert: () => ({
      values: (v: Row) => ({
        onConflictDoUpdate: ({ set }: { set: Partial<Row> }) => {
          const i = rows.findIndex((r) => r.email === v.email);
          if (i >= 0) rows[i] = { ...rows[i]!, ...set } as Row;
          else rows.push({ ...v });
          return Promise.resolve();
        },
      }),
    }),
    delete: () => ({
      where: (p: { val: unknown }) => {
        const i = rows.findIndex((r) => r.email === p.val);
        if (i >= 0) rows.splice(i, 1);
        return Promise.resolve();
      },
    }),
  },
}));

const { suppressEmail, isSuppressed, unsuppressEmail, suppressionForEvent } = await import("./emailSuppression");

beforeEach(() => {
  rows.length = 0;
  shouldThrow = false;
});

describe("suppressionForEvent", () => {
  it("suppresses ALL mail after a hard bounce — the address does not exist", () => {
    expect(
      suppressionForEvent("email.bounced", { to: "gone@example.com", bounce: { type: "Permanent", subType: "NoEmail" } }),
    ).toMatchObject({ email: "gone@example.com", scope: "all", reason: "hard_bounce" });
  });

  // THE one to get right. A soft bounce is a full mailbox or a transient
  // server problem; it clears by itself. Suppressing on one would quietly cut
  // off a real user whose inbox was briefly over quota.
  it("does NOT suppress on a soft bounce", () => {
    expect(
      suppressionForEvent("email.bounced", { to: "full@example.com", bounce: { type: "Transient", subType: "MailboxFull" } }),
    ).toBeNull();
  });

  it("suppresses only BULK mail after a complaint", () => {
    expect(suppressionForEvent("email.complained", { to: "cross@example.com" })).toMatchObject({
      scope: "bulk",
      reason: "complaint",
    });
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

describe("isSuppressed", () => {
  it("blocks everything for a hard-bounced address", async () => {
    await suppressEmail("gone@example.com", "all", "hard_bounce");
    expect(await isSuppressed("gone@example.com", "bulk")).toBe(true);
    expect(await isSuppressed("gone@example.com", "account")).toBe(true);
  });

  // The decision that keeps a newsletter complaint from locking someone out of
  // their own account.
  it("blocks bulk but NOT account mail for someone who complained", async () => {
    await suppressEmail("cross@example.com", "bulk", "complaint");
    expect(await isSuppressed("cross@example.com", "bulk")).toBe(true);
    expect(await isSuppressed("cross@example.com", "account")).toBe(false);
  });

  it("does not block an address that was never suppressed", async () => {
    expect(await isSuppressed("fine@example.com", "bulk")).toBe(false);
  });

  it("matches regardless of case or surrounding whitespace", async () => {
    await suppressEmail("  Mixed@Example.COM ", "all", "hard_bounce");
    expect(await isSuppressed("mixed@example.com", "account")).toBe(true);
  });

  // Fails OPEN on purpose. A database blip that silently stopped every sign-in
  // code in the system would be far worse than one extra message to an address
  // that bounced.
  it("sends anyway if the lookup throws, rather than silencing all mail", async () => {
    await suppressEmail("gone@example.com", "all", "hard_bounce");
    shouldThrow = true;
    expect(await isSuppressed("gone@example.com", "account")).toBe(false);
  });
});

describe("suppressEmail", () => {
  it("upserts rather than accumulating rows for a repeated webhook", async () => {
    await suppressEmail("dup@example.com", "bulk", "complaint");
    await suppressEmail("dup@example.com", "bulk", "complaint");
    expect(rows.filter((r) => r.email === "dup@example.com")).toHaveLength(1);
  });

  // Someone who complained AND whose mailbox was then deleted is both; the
  // stricter rule is the true one. Widening back to bulk-only would resume
  // mailing an address that does not exist.
  it("never downgrades an existing 'all' back to 'bulk'", async () => {
    await suppressEmail("both@example.com", "all", "hard_bounce");
    await suppressEmail("both@example.com", "bulk", "complaint");
    expect(await isSuppressed("both@example.com", "account")).toBe(true);
  });

  it("does upgrade a 'bulk' to 'all' when the address later hard-bounces", async () => {
    await suppressEmail("up@example.com", "bulk", "complaint");
    await suppressEmail("up@example.com", "all", "hard_bounce");
    expect(await isSuppressed("up@example.com", "account")).toBe(true);
  });

  it("ignores an empty address instead of writing a blank row", async () => {
    await suppressEmail("   ", "all", "hard_bounce");
    expect(rows).toHaveLength(0);
  });
});

describe("unsuppressEmail", () => {
  it("lifts a suppression so the address receives mail again", async () => {
    await suppressEmail("fixed@example.com", "all", "hard_bounce");
    await unsuppressEmail("fixed@example.com");
    expect(await isSuppressed("fixed@example.com", "account")).toBe(false);
  });
});
