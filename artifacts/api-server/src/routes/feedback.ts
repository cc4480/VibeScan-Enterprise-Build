/**
 * "What did you think, after actually using it?"
 *
 * The free-scan cap exists to get people testing the scanner on apps they
 * own and telling us what worked. Submitting feedback never requires an
 * account — an anonymous scan is still a real user with a real opinion, and
 * account creation must never be the price of being heard.
 */
import { Router, type IRouter } from "express";
import { db, feedbackTable } from "@workspace/db";

const router: IRouter = Router();

router.post("/feedback", async (req, res): Promise<void> => {
  const message = typeof req.body?.message === "string" ? req.body.message.trim() : "";
  if (!message) {
    res.status(400).json({ error: "Feedback message is required" });
    return;
  }
  if (message.length > 5000) {
    res.status(400).json({ error: "Feedback message is too long" });
    return;
  }

  const rating =
    typeof req.body?.rating === "number" && Number.isInteger(req.body.rating)
      ? Math.min(5, Math.max(1, req.body.rating))
      : null;
  const context = typeof req.body?.context === "string" ? req.body.context.slice(0, 200) : null;

  const userId = req.isAuthenticated() ? req.user.id : null;
  const email = req.isAuthenticated() ? (req.user.email ?? null) : null;

  try {
    await db.insert(feedbackTable).values({ userId, email, message, rating, context });
    req.log.info({ userId, rating, context }, "Feedback recorded");
    res.status(201).json({ recorded: true });
  } catch (err) {
    req.log.error({ err }, "Failed to record feedback");
    res.status(500).json({ error: "Failed to record feedback" });
  }
});

export default router;
