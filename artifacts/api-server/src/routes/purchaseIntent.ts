/**
 * "Tell me when I can buy more scans."
 *
 * The free-scan cap is currently a wall with nothing behind it — there is no
 * Checkout Session creation yet (see lib/stripe.ts), so someone who spends all
 * five scans is told to come back later and leaves without trace. That is the
 * worst moment to learn nothing: they have just used the product enough to run
 * out, which is the strongest buying signal the app can observe.
 *
 * This records that signal and nothing else. It does not take payment details,
 * does not promise a price, and does not subscribe anyone to marketing — the
 * product-updates audience is a separate, separately-consented thing in
 * lib/mailer.ts. Retire this route with the table when checkout ships.
 */
import { Router, type IRouter } from "express";
import { db, purchaseIntentsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { trialScansUsedBy, FREE_TRIAL_SCAN_LIMIT } from "../lib/freeTrial";

const router: IRouter = Router();

router.get("/purchase-intent", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const [row] = await db
      .select({ createdAt: purchaseIntentsTable.createdAt })
      .from(purchaseIntentsTable)
      .where(eq(purchaseIntentsTable.userId, req.user.id))
      .limit(1);

    res.json({
      registered: row != null,
      scansUsed: await trialScansUsedBy(req.user.id),
      scanLimit: FREE_TRIAL_SCAN_LIMIT,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to read purchase intent");
    res.status(500).json({ error: "Failed to read purchase intent" });
  }
});

router.post("/purchase-intent", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  // An account with no address on file cannot be told anything later, so
  // recording the intent would be recording a number we can never act on.
  const email = req.user.email;
  if (!email) {
    res.status(400).json({ error: "Your account has no email address on file" });
    return;
  }

  try {
    // Idempotent: pressing the button twice is one person, not two signals.
    // onConflictDoNothing rather than an update, because the first press is
    // when they wanted it — that timestamp is the interesting one.
    await db
      .insert(purchaseIntentsTable)
      .values({ userId: req.user.id, email })
      .onConflictDoNothing({ target: purchaseIntentsTable.userId });

    req.log.info({ userId: req.user.id }, "Purchase intent recorded");
    res.status(201).json({ registered: true });
  } catch (err) {
    req.log.error({ err }, "Failed to record purchase intent");
    res.status(500).json({ error: "Failed to record purchase intent" });
  }
});

export default router;
