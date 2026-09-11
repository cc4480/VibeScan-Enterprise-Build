/**
 * Resend delivery events: bounces and spam complaints.
 *
 * This is the feedback loop that was missing entirely. Without it every send to
 * a dead address repeated forever and every "mark as spam" went unseen — both
 * of which erode the sender reputation that decides whether wanted mail reaches
 * the inbox, including the sign-in codes people now need to log in.
 *
 * Configure in the Resend dashboard: add an endpoint at
 * https://secscan.us/api/email/webhook subscribed to `email.bounced` and
 * `email.complained`, then set RESEND_WEBHOOK_SECRET to the signing secret it
 * shows (`whsec_…`).
 */

import { Router, type IRouter, type Request, type Response } from "express";
import { suppressEmail, suppressionForEvent } from "../lib/emailSuppression";
import { verifySvixSignature } from "../lib/svixSignature";

const router: IRouter = Router();

router.post("/email/webhook", async (req: Request, res: Response): Promise<void> => {
  const secret = process.env["RESEND_WEBHOOK_SECRET"];
  if (!secret) {
    // 503, not 200. Answering OK would make Resend believe events are being
    // consumed while they are dropped, and the dashboard would show a healthy
    // endpoint delivering into nothing.
    req.log.error("RESEND_WEBHOOK_SECRET is not set — delivery events are being discarded");
    res.status(503).json({ error: "Webhook not configured" });
    return;
  }

  // express.raw is mounted for this path (see app.ts). The signature covers the
  // bytes as sent: re-serialising parsed JSON changes key order and whitespace
  // and will never match.
  const raw = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "";

  const verified = verifySvixSignature(secret, raw, {
    id: req.headers["svix-id"] as string | undefined,
    timestamp: req.headers["svix-timestamp"] as string | undefined,
    signature: req.headers["svix-signature"] as string | undefined,
  });

  if (!verified.ok) {
    // Unverified, this endpoint would let anyone who found the URL forge a
    // bounce for any address and permanently stop that person receiving
    // sign-in codes — a denial of service against a named account.
    req.log.warn({ reason: verified.reason }, "Rejected an unverified Resend webhook");
    res.status(401).json({ error: "Invalid signature" });
    return;
  }

  let event: { type?: string; data?: Record<string, unknown> };
  try {
    event = JSON.parse(raw);
  } catch {
    res.status(400).json({ error: "Malformed payload" });
    return;
  }

  const decision = suppressionForEvent(String(event.type ?? ""), event.data ?? {});
  if (!decision) {
    // A delivered/opened/soft-bounced event, or one we do not act on. Still a
    // 200 — anything else makes Resend retry an event we deliberately ignored.
    res.json({ ok: true, suppressed: false });
    return;
  }

  try {
    await suppressEmail(decision.email, decision.scope, decision.reason, decision.detail);
    req.log.info(
      { scope: decision.scope, reason: decision.reason },
      "Suppressed an address after a delivery event",
    );
    res.json({ ok: true, suppressed: true });
  } catch (err) {
    // 500 so Resend retries. Losing a suppression means continuing to mail an
    // address that bounced, which is the thing this exists to stop.
    req.log.error({ err }, "Could not record an email suppression");
    res.status(500).json({ error: "Could not record suppression" });
  }
});

export default router;
