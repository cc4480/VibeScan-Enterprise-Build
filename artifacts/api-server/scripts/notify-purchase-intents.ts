/**
 * Keep the promise made before checkout existed.
 *
 * Everyone who clicked "Email me when I can buy scans" (purchase_intents) was
 * told: "we'll email you the moment there is" a way to buy. Nothing sent that
 * email. Run this ONCE, after payments are live on secscan.us — never before,
 * or it announces a checkout nobody can use.
 *
 * DRY RUN BY DEFAULT: lists who would be emailed and sends nothing.
 *
 *   DATABASE_URL=... RESEND_API_KEY=... APP_ORIGIN=https://secscan.us \
 *     npx tsx artifacts/api-server/scripts/notify-purchase-intents.ts          # dry run
 *   ... notify-purchase-intents.ts --send                                     # really send
 *
 * Safe to re-run: each person is marked `notified_at` only after Resend
 * accepts their email, so a partial failure is finished by running it again,
 * and nobody is emailed twice.
 *
 * Refuses to send unless STRIPE_SECRET_KEY is set in the same environment — a
 * cheap guard against announcing payments from a shell where they are not on.
 */
import { db, purchaseIntentsTable } from "@workspace/db";
import { eq, isNull } from "drizzle-orm";
import { sendPaymentsLiveEmail } from "../src/lib/mailer";

const SEND = process.argv.includes("--send");

async function main(): Promise<void> {
  const pending = await db
    .select({ id: purchaseIntentsTable.id, email: purchaseIntentsTable.email })
    .from(purchaseIntentsTable)
    .where(isNull(purchaseIntentsTable.notifiedAt));

  console.log(`${pending.length} people are waiting to hear that they can buy.`);
  if (!SEND) {
    for (const p of pending) console.log(`  would email ${p.email}`);
    console.log("\nDry run — nothing sent. Re-run with --send once payments are live.");
    return;
  }

  if (!process.env["STRIPE_SECRET_KEY"]) {
    console.error("Refusing to send: STRIPE_SECRET_KEY is not set, so payments may not be live.");
    process.exitCode = 1;
    return;
  }
  if (!process.env["RESEND_API_KEY"]) {
    console.error("Refusing to send: RESEND_API_KEY is not set.");
    process.exitCode = 1;
    return;
  }

  const tally = { sent: 0, suppressed: 0, failed: 0 };
  for (const p of pending) {
    const outcome = await sendPaymentsLiveEmail(p.email);
    tally[outcome]++;
    // Suppressed addresses are marked too: they must never be retried, and
    // "notified" here means "handled", not "delivered".
    if (outcome !== "failed") {
      await db
        .update(purchaseIntentsTable)
        .set({ notifiedAt: new Date() })
        .where(eq(purchaseIntentsTable.id, p.id));
    }
    console.log(`  ${outcome.padEnd(10)} ${p.email}`);
    // Stay well under Resend's rate limit.
    await new Promise((r) => setTimeout(r, 250));
  }

  console.log(`\nSent ${tally.sent}, skipped ${tally.suppressed} suppressed, ${tally.failed} failed.`);
  if (tally.failed > 0) {
    console.log("Failed ones are still pending — run again to retry them.");
    process.exitCode = 1;
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => process.exit());
