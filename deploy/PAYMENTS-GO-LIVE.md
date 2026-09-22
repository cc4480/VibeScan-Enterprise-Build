# Turning payments on

What is sold (decided 2026-09-22):

| Product | Price | What it gives |
|---|---|---|
| **SecScan Pro** | $50 / month | Monitoring for up to 3 sites + 5 full scans every month (no rollover) |
| 1 scan credit | $12 | One full scan, never expires |
| 5-scan pack | $50 | Five scans, never expire |
| 20-scan pack | $160 | Twenty scans, never expire |

Every account also gets 2 free scans. Scans are paid for in this order: free →
this month's plan scans → credits.

All prices live in code (`lib/stripe.ts` `PRICE_MAP`, `lib/plans.ts`). You do
**not** create products or prices in Stripe — checkout builds them from the code.

Until the steps below are done, the site shows prices with "not live yet" and
nothing can be bought. Shipping the code changes nothing visible to customers
beyond the pricing copy.

---

## 0. Push order

Push `VibeScan-Enterprise-Build` (secscan.us) and `secscan-info` (secscan.info)
**together**, once Stripe test mode works end to end. secscan.info's pricing
copy (commit "Replace \"free during early access\" with the real pricing")
quotes SecScan Pro; published before checkout is live, it would advertise a
plan nobody can buy.

## 1. Test mode first (do not skip)

1. Stripe dashboard → toggle **Test mode** on (top right).
2. **Developers → API keys** → copy the **Secret key** (`sk_test_…`).
3. **Developers → Webhooks → Add endpoint**
   - URL: `https://secscan.us/api/scan/webhook`
   - Events — select exactly these five:
     - `checkout.session.completed`
     - `checkout.session.async_payment_succeeded`
     - `invoice.paid`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
   - Save, then **Reveal** the signing secret (`whsec_…`).
4. **Settings → Billing → Customer portal** → turn on: cancel subscriptions,
   update payment methods, view invoices → **Save**. (Without this, "Manage or
   cancel" in Settings cannot open.)
5. Railway → project → **web** service → **Variables**, add:
   - `STRIPE_SECRET_KEY` = the `sk_test_…` key
   - `STRIPE_WEBHOOK_SECRET` = the `whsec_…` secret

   Set **both** at the same time. With only the key, customers could pay and
   never be credited — the server logs an error at boot if that happens.

## 2. Test every path with Stripe's test card

Card `4242 4242 4242 4242`, any future date, any CVC.

- [ ] Buy the 5-scan pack → Settings shows **5 credits**.
- [ ] Subscribe to Pro → Settings shows **Active**, **5 plan scans**, a renewal date.
- [ ] Run a scan → plan scans drop to 4 (credits untouched).
- [ ] Settings → **Manage or cancel** → cancel → Settings shows **Cancelled**, plan scans 0.
- [ ] Stripe → Webhooks → your endpoint: every delivery shows **200**.
- [ ] Declined card `4000 0000 0000 0002` → nothing is granted.

## 3. Go live

1. Toggle **Test mode off** and repeat steps 1.2–1.4 in live mode (live mode
   has its own keys, webhook endpoint and portal settings).
2. Replace both Railway variables with the **live** `sk_live_…` and `whsec_…`.
3. Buy one real $12 credit with your own card, confirm it lands, refund it from
   the Stripe dashboard.

## 4. Decide before switching monitoring to paid

Monitoring is free for everyone today. It becomes Pro-only when
`MONITORING_REQUIRES_PLAN=true` is set on the **web** and **secscan** services.
The moment it is set, **every existing free monitor stops** (hourly checks,
rescans, CVE and certificate alerts) for anyone without a plan.

Before flipping it, decide what existing monitor users get — for example,
grandfather them (a `billing_subscriptions` row with `grandfathered = true`)
or email them a notice first. Then update secscan.info's monitoring page,
which currently describes monitoring without mentioning a plan.

## Refunds and disputes

Refunding in Stripe returns the customer's money but does **not** remove
credits or end a plan. Cancel the subscription in Stripe if refunding a plan;
for a credit pack, decide case by case.
