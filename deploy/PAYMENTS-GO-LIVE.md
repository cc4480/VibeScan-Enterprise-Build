# Turning payments on

What is sold (decided 2026-09-24; replaces the 2026-09-22 single $50 plan):

| Product | Price | What it gives |
|---|---|---|
| **SecScan Starter** | $19 / month | Monitoring for 1 site + 20 full scans every month (no rollover) |
| **SecScan Pro** | $49 / month | Monitoring for up to 5 sites + 100 full scans every month (no rollover) |
| 10-scan pack | $12 | Ten scans, never expire |
| 50-scan pack | $49 | Fifty scans, never expire |

Every account also gets 3 free scans each calendar month (UTC), renewing on
the 1st; unused ones do not carry over. Scans are paid for in this order: free →
this month's plan scans → credits.

All prices live in code (`lib/stripe.ts` `PRICE_MAP`, `lib/plans.ts`). You do
**not** create products or prices in Stripe — checkout builds them from the code.

Until the steps below are done, the site shows prices with "not live yet" and
nothing can be bought. Shipping the code changes nothing visible to customers
beyond the pricing copy.

---

## 0. Where things stand (2026-09-24)

All payment code is **already deployed** on secscan.us and switched off: no
`STRIPE_*` variables are set, so every price shows "not live yet" and nothing
can be bought. secscan.info already describes the plan and the packs.

**Going live is configuration only — no code change, no push:** Stripe
dashboard settings (below) plus two Railway variables. Do it **last**, after
QA, once everything else is signed off.

Order: account setup (0b) → test mode locally (1–2) → go live (3).

## 0b. Stripe account setup (once, in the dashboard)

These are what a customer sees on the checkout page and their bank statement.

- **Settings → Business details:** public business name **SecScan**, support
  email, website `https://secscan.us`.
- **Settings → Public details → Statement descriptor:** `SECSCAN` (what shows
  on the card statement; short and recognisable reduces chargebacks).
- **Settings → Branding:** SecScan logo/icon, brand colour `#22c55e`, accent
  `#09090b`. Checkout and receipts use these.
- **Settings → Customer emails:** turn on **Successful payments**, **Refunds**
  and **Failed payments** (see step 3.5).
- Payout bank account and identity verification complete — Stripe will not pay
  out (and may pause charges) until they are.

## 1. Test mode, locally (do not skip)

1. Stripe dashboard → toggle **Test mode** on (top right).
2. **Developers → API keys** → copy the **Secret key** (`sk_test_…`).
3. Install the Stripe CLI, run `stripe login`, then
   `stripe listen --forward-to localhost:<PORT>/api/scan/webhook`. It prints a
   webhook signing secret (`whsec_…`) and forwards every test event to your
   machine.
4. Run SecScan locally with `STRIPE_SECRET_KEY=sk_test_…` and that
   `STRIPE_WEBHOOK_SECRET`. Set **both** at once — a key alone takes money it
   cannot credit, and the server logs an error at boot if you do that.
5. Still in test mode: **Settings → Billing → Customer portal** → turn on
   cancel subscriptions (at end of billing period), update payment methods,
   view invoices → **Save**. Test and live mode keep separate portal settings.

## 2. Test every path with Stripe's test card

Card `4242 4242 4242 4242`, any future date, any CVC.

- [ ] Buy the 5-scan pack → Settings shows **5 credits**.
- [ ] Subscribe to Pro → Settings shows **Active**, **5 plan scans**, a renewal date.
- [ ] Run a scan → plan scans drop to 4 (credits untouched).
- [ ] Settings → **Manage or cancel** → cancel → Settings shows **Cancelled**, plan scans 0.
- [ ] Stripe → Webhooks → your endpoint: every delivery shows **200**.
- [ ] Declined card `4000 0000 0000 0002` → nothing is granted.

## 3. Go live (last step, after QA)

1. Toggle **Test mode off**. **Developers → API keys** → copy the live secret
   key (`sk_live_…`).
2. **Developers → Webhooks → Add endpoint**
   - URL: `https://secscan.us/api/scan/webhook`
   - Events — select exactly these five:
     - `checkout.session.completed`
     - `checkout.session.async_payment_succeeded`
     - `invoice.paid`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
   - Save, then **Reveal** the signing secret (`whsec_…`).
3. **Settings → Billing → Customer portal** → turn on: cancel subscriptions
   (at end of billing period), update payment methods, view invoices → **Save**.
   Without this, "Manage or cancel" in Settings cannot open.
4. Railway → **web** service → **Variables**: add `STRIPE_SECRET_KEY` and
   `STRIPE_WEBHOOK_SECRET` (the live values), both at once.
5. **Settings → Customer emails** → turn on **Successful payments** and
   **Failed payments** (and the card-update reminders). SecScan emails its own
   receipt for credit packs, but a monthly renewal's receipt — and the "your
   card was declined" email — come only from Stripe.
6. Buy one real $12 pack (10 credits) with your own card, confirm it lands, refund it from
   the Stripe dashboard.
7. **Tell the people who asked.** Everyone who clicked "Email me when I can buy
   scans" was promised an email. Dry run first, then send (once):
   ```
   DATABASE_URL=… RESEND_API_KEY=… STRIPE_SECRET_KEY=… APP_ORIGIN=https://secscan.us      npx tsx artifacts/api-server/scripts/notify-purchase-intents.ts          # lists them
   …notify-purchase-intents.ts --send                                         # emails them
   ```
   Safe to re-run: each person is marked as told only once the email is accepted.
8. **Update the public docs that describe today's state** (repo `~/secscan-info`).
   While payments are off, `/ai-editors` says "Buying more scans isn't open yet"
   (troubleshooting table, "You've used this month's 3 free scans") and the app shows
   "Paid scans are coming soon". Once checkout is live, change both to point at
   the pricing. `/monitoring` already advertises Starter ($19/month, 1 site, 20
   scans) and Pro ($49/month, 5 sites, 100 scans); that page is only true once
   step 6 has passed.

## Sales tax

Checkout does not collect sales tax or VAT. If you need to, turn on **Stripe
Tax** in the dashboard and add `automatic_tax: { enabled: true }` to both
checkout sessions in `routes/checkout.ts` — a decision for you and your
accountant, not a default.

## 4. Decide before switching monitoring to paid

Monitoring is free for everyone today. It becomes Pro-only when
`MONITORING_REQUIRES_PLAN=true` is set on the **web** and **secscan** services.
The moment it is set, **every existing free monitor stops** (hourly checks,
rescans, CVE and certificate alerts) for anyone without a plan.

Before flipping it, decide what existing monitor users get. To keep them
monitored for free (recommended — they signed up when monitoring had no plan),
run the grandfather script first; it is a dry run unless `--apply` is given,
and safe to re-run:

```
DATABASE_URL=… npx tsx artifacts/api-server/scripts/grandfather-monitor-users.ts           # shows who
DATABASE_URL=… npx tsx artifacts/api-server/scripts/grandfather-monitor-users.ts --apply   # does it
```

Or email them a notice first instead. Then update secscan.info's monitoring page,
which currently describes monitoring without mentioning a plan.

## Refunds and disputes

Refunding in Stripe returns the customer's money but does **not** remove
credits or end a plan. Cancel the subscription in Stripe if refunding a plan;
for a credit pack, decide case by case.
