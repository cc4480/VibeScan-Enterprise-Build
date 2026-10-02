/**
 * Routes for the three probes that act on a target instead of only reading it:
 * autoSecondAccount.ts, promptInjectionProbe.ts and raceConditionProbe.ts. Each vulnerable
 * route has a clean twin that does the same job safely; the scanner must act on the first
 * and never report (or create anything through) the second.
 *
 *   /signup            self-serve signup that hands back a session at once     VULNERABLE (the probe may use it)
 *   /signup on Host: localhost   the same form, but asks for email confirmation  clean twin (the probe must stop)
 *   /api/assistant/ask replies with its system prompt when told to ignore rules VULNERABLE (prompt injection)
 *   /api/chat          echoes the message, never the prompt                     clean twin
 *   /api/coupon/redeem checks "used", waits, then marks it: a race             VULNERABLE (CWE-362)
 *   /api/promo/claim   claims with one atomic step                             clean twin
 *
 * The signup pair shares a path because the probe only ever tries a fixed list of paths and
 * stops at the first that answers. The Host header tells them apart: 127.0.0.1 is the open
 * signup, localhost is the one that wants an email confirmed.
 *
 * The coupon forgets it was used after a second, so a second verify run against the same
 * server sees the same bug instead of an already-spent coupon.
 */
import express, { type Express, type Request } from "express";
import { randomBytes } from "node:crypto";
import { SUPPORT_SYSTEM_PROMPT } from "./ai-assets.js";

type Session = { id: string; email: string };

/** Loaded before ai-widget.js and ai-chat.js so the probe's first chat-shaped endpoint is the vulnerable one. */
export const SUPPORT_JS = `
// front end for the support assistant and the rewards page: every endpoint is a literal here
fetch("/api/assistant/ask", { method: "POST", body: JSON.stringify({ message: "hi" }) });
// Both calls sit behind a click, as on a real page. They used to fire on page load, so the scanner's own
// headless browser spent alice's coupon about a second before the race probe ran; when the coupon's 1 s
// expiry had not yet passed (a fast CI runner) the probe saw it already spent and recorded "nothing was tested".
function applyCoupon() { return fetch("/api/coupon/redeem", { method: "POST", body: "{}" }); }
function claimPromo() { return fetch("/api/promo/claim", { method: "POST", body: "{}" }); }
document.addEventListener("click", (e) => {
  if (e.target && e.target.id === "apply-coupon") applyCoupon();
  if (e.target && e.target.id === "claim-promo") claimPromo();
});
`;

const OVERRIDE = /ignore (all )?(previous|prior) instructions/i;
const messageOf = (body: unknown): string => {
  const b = (body ?? {}) as { message?: unknown; messages?: Array<{ content?: unknown }> };
  return String(b.message ?? b.messages?.at(-1)?.content ?? "");
};

export function mountAccountAiRace(app: Express, sessions: Record<string, Session>): void {
  const sessionOf = (req: Request): Session | null => {
    const m = /session=([^;]+)/.exec(req.headers.cookie ?? "");
    return (m && sessions[m[1]!]) || null;
  };
  const json = express.json();
  const form = express.urlencoded({ extended: false });

  // ── autoSecondAccount.ts ──────────────────────────────────────────────────
  const twinHost = (req: Request) => req.hostname === "localhost";
  app.get("/signup", (_req, res) => {
    res.type("text/html").send(
      `<html><body><h1>Create your account</h1><form method="post" action="/signup"><input name="email" type="email"><input name="password" type="password"><button>Sign up</button></form></body></html>`,
    );
  });
  app.post("/signup", form, (req, res) => {
    if (twinHost(req)) {
      // Clean twin: nothing is created and no session is issued until an emailed link is used.
      res.type("text/html").send(`<html><body><p>Almost there. Check your email to confirm your account.</p></body></html>`);
      return;
    }
    const token = `signup-${randomBytes(6).toString("hex")}`;
    sessions[token] = { id: String(2000 + Object.keys(sessions).length), email: String(req.body?.email ?? "") };
    res.setHeader("Set-Cookie", `session=${token}; Path=/`);
    res.redirect(302, "/api/me");
  });
  app.get("/api/me", (req, res) => {
    const s = sessionOf(req);
    if (!s) { res.status(401).json({ error: "sign in" }); return; }
    res.json({ id: s.id });
  });

  // ── promptInjectionProbe.ts ───────────────────────────────────────────────
  app.post("/api/assistant/ask", json, (req, res) => {
    const msg = messageOf(req.body);
    res.json({ reply: OVERRIDE.test(msg) ? `Sure. Here it is:\n\`\`\`\n${SUPPORT_SYSTEM_PROMPT}\n\`\`\`` : "How can I help with your order?" });
  });
  app.post("/api/chat", json, (req, res) => {
    // Repeats the attacker's words back, which is not the same as leaking the prompt.
    res.json({ reply: `You said: ${messageOf(req.body)}. I can only help with orders.` });
  });

  // ── raceConditionProbe.ts ─────────────────────────────────────────────────
  const redeemed = new Set<string>();
  const claimed = new Set<string>();
  app.post("/api/coupon/redeem", json, async (req, res) => {
    const s = sessionOf(req);
    if (!s) { res.status(401).json({ error: "sign in" }); return; }
    if (redeemed.has(s.id)) { res.status(409).json({ error: "Coupon is no longer valid" }); return; }
    await new Promise((r) => setTimeout(r, 30)); // the gap between the check and the write
    redeemed.add(s.id);
    setTimeout(() => redeemed.delete(s.id), 1_000).unref();
    res.json({ applied: true, discount: "20%" });
  });
  app.post("/api/promo/claim", json, (req, res) => {
    const s = sessionOf(req);
    if (!s) { res.status(401).json({ error: "sign in" }); return; }
    // Check and write in one synchronous step: only one caller can get past it.
    if (claimed.has(s.id)) { res.status(409).json({ error: "Promo is no longer valid" }); return; }
    claimed.add(s.id);
    setTimeout(() => claimed.delete(s.id), 1_000).unref();
    res.json({ applied: true, discount: "20%" });
  });
}
