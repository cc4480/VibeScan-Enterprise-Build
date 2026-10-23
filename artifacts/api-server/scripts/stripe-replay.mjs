/**
 * Replays REAL Stripe test-mode events into a local webhook.
 *
 * Stripe cannot reach localhost, so instead of a tunnel this pulls the events
 * Stripe generated for real checkouts (Stripe API + STRIPE_SECRET_KEY) and
 * delivers each one to the real /api/scan/webhook route, signed with the local
 * STRIPE_WEBHOOK_SECRET exactly the way Stripe signs. That exercises the route,
 * signature check and handler against genuine payload shapes.
 *
 *   STRIPE_SECRET_KEY=sk_test_... STRIPE_WEBHOOK_SECRET=whsec_... \
 *     node scripts/stripe-replay.mjs [minutes-back=90] [base-url=http://localhost:8099]
 *
 * Test-mode keys only: it refuses anything else.
 */
import Stripe from "stripe";

const key = process.env.STRIPE_SECRET_KEY ?? "";
const secret = process.env.STRIPE_WEBHOOK_SECRET ?? "";
if (!key.startsWith("sk_test_")) throw new Error("Refusing to run without a sk_test_ key.");
if (!secret) throw new Error("STRIPE_WEBHOOK_SECRET is required (the local signing secret).");

const minutes = Number(process.argv[2] ?? 90);
const base = process.argv[3] ?? "http://localhost:8099";
const stripe = new Stripe(key);

const since = Math.floor(Date.now() / 1000) - minutes * 60;
const events = [];
for await (const e of stripe.events.list({ created: { gte: since }, limit: 100 })) events.push(e);
events.sort((a, b) => a.created - b.created);

async function deliver(event) {
  const payload = JSON.stringify(event);
  const header = stripe.webhooks.generateTestHeaderString({ payload, secret });
  const res = await fetch(`${base}/api/scan/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "stripe-signature": header },
    body: payload,
  });
  return `${res.status} ${(await res.text()).slice(0, 80)}`;
}

console.log(`${events.length} event(s) in the last ${minutes} min`);
for (const e of events) console.log(`  ${e.type.padEnd(40)} ${await deliver(e)}`);

// A second delivery of every event must be a no-op: Stripe retries.
console.log("--- redelivering every event (must change nothing) ---");
for (const e of events) console.log(`  ${e.type.padEnd(40)} ${await deliver(e)}`);
