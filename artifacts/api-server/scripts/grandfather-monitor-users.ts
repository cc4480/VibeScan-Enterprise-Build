/**
 * Give everyone already monitoring a permanent, free plan.
 *
 * MUST BE RUN BEFORE `MONITORING_REQUIRES_PLAN` IS EVER SET TO "true".
 *
 * Monitoring shipped free and ungated. The people using it did not sign up for
 * a plan because there was none to sign up for, and turning enforcement on
 * without this would silently stop watching their sites — the exact failure
 * this whole feature exists to prevent for other people's applications.
 *
 * Idempotent: it skips users who already have a billing row, so it is safe to
 * run again before the flag flips in case anyone subscribed in between.
 *
 * Usage:
 *   DATABASE_URL=... npx tsx artifacts/api-server/scripts/grandfather-monitor-users.ts [--apply]
 *
 * Without --apply it prints what it would do and writes nothing.
 */
import { db, monitorSubscriptionsTable, billingSubscriptionsTable } from "@workspace/db";
import { eq } from "drizzle-orm";

/**
 * Floor for a grandfathered allowance.
 *
 * Set to the original SecScan Pro site limit (3) rather than to each user's current count: a
 * grandfathered user who happens to be watching one site today would otherwise
 * be unable to add a second, which reads as a downgrade on the day we start
 * charging other people. Anyone already above this keeps their higher number.
 */
const GRANDFATHER_FLOOR = 3;

async function main(): Promise<void> {
  const apply = process.argv.includes("--apply");

  const subs = await db
    .select({
      userId: monitorSubscriptionsTable.userId,
      status: monitorSubscriptionsTable.status,
    })
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const countByUser = new Map<string, number>();
  for (const s of subs) {
    countByUser.set(s.userId, (countByUser.get(s.userId) ?? 0) + 1);
  }

  if (countByUser.size === 0) {
    console.log("No active monitor subscriptions — nothing to grandfather.");
    return;
  }

  console.log(`${countByUser.size} user(s) with active monitoring:\n`);

  let created = 0;
  let skipped = 0;

  for (const [userId, activeCount] of countByUser) {
    const [existing] = await db
      .select({ id: billingSubscriptionsTable.id })
      .from(billingSubscriptionsTable)
      .where(eq(billingSubscriptionsTable.userId, userId))
      .limit(1);

    const urlLimit = Math.max(activeCount, GRANDFATHER_FLOOR);

    if (existing) {
      console.log(`  ${userId}  monitoring ${activeCount} — already has a billing row, skipping`);
      skipped++;
      continue;
    }

    console.log(`  ${userId}  monitoring ${activeCount} → grandfathered, urlLimit ${urlLimit}`);

    if (apply) {
      await db.insert(billingSubscriptionsTable).values({
        userId,
        plan: "grandfathered",
        status: "active",
        urlLimit,
        grandfathered: true,
        // No currentPeriodEnd: this does not renew and must never expire.
        currentPeriodEnd: null,
      });
      created++;
    }
  }

  console.log(
    apply
      ? `\nDone. ${created} created, ${skipped} skipped.`
      : `\nDRY RUN — nothing written. Re-run with --apply to create ${countByUser.size - skipped} row(s).`,
  );
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Failed:", err);
    process.exit(1);
  });
