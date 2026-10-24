# Turning payments on

What is sold (decided 2026-10-03; replaces the 2026-09-24 Starter, Pro and credit packs):

| Product | Price | What it gives |
|---|---|---|
| **SecScan Unlimited** | $19 / month | Unlimited full scans (fair use: 5 an hour, 20 a day per account by default) + monitoring for up to 3 sites |

Starter ($19, 3 sites, 20 scans), Pro ($49, 5 sites, 100 scans) and the 10 and 50-scan packs are
**not sold**. Starter and Pro stay in `lib/plans.ts` so a row carrying one still resolves, and the
pack grant table stays in `lib/stripe.ts` so a checkout opened before the change and paid after it
is still credited. `PACKS_ON_SALE` is empty, and the subscription endpoint refuses a plan that is not on sale.

Every account also gets 3 free scans each calendar month (UTC), renewing on
the 1st; unused ones do not carry over. Scans are paid for in this order: an unlimited
plan (nothing is counted) → free → a counted plan's scans (legacy only) → credits (a balance already held).

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

- [ ] The pricing page and Settings show one plan, **SecScan Unlimited $19**, and no credit packs.
- [ ] Subscribe → Settings shows **SecScan Unlimited**, **Active**, **Unlimited scans on your plan**, a renewal date.
- [ ] Run several scans → still **Unlimited**; the free scans are untouched.
- [ ] Settings → **Manage or cancel** → cancel → Settings shows **Cancelled**, and scans fall back to the free ones.
- [ ] Stripe → Webhooks → your endpoint: every delivery shows **200**.
- [ ] Declined card `4000 0000 0000 0002` → nothing is granted.
- [ ] With `MONITORING_REQUIRES_PLAN=true` locally: a cancelled plan stops monitors (rows kept); resubscribing restarts them.
- [ ] With `MONITORING_REQUIRES_PLAN=true` locally and no plan: the first monitor is accepted, a second is refused with the plans shown, and its rescans are no more often than weekly (`FREE_MONITOR_SITES=0` turns the free site off).
- [ ] An account that was monitoring before the flag (run `scripts/grandfather-monitor-users.ts --apply` first) keeps all its sites.
- [ ] Report → Share → **Get badge** on a scan of a verified domain: the image loads on another origin, shows the grade and date only, and **Remove badge** turns it into "badge not found". On a scan of an unverified domain, **Get badge** is refused with the reason. Migration `0025` creates the `report_badges` table, and it must have run.

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
   `STRIPE_WEBHOOK_SECRET` (the live values), both at once. In the same
   change set `MONITORING_REQUIRES_PLAN=true` on **both** services (web and
   secscan), so monitoring needs a plan from the moment payments open.
5. **Settings → Customer emails** → turn on **Successful payments** and
   **Failed payments** (and the card-update reminders). SecScan emails its own
   receipt for credit packs, but a monthly renewal's receipt — and the "your
   card was declined" email — come only from Stripe.
6. Subscribe once for real ($19) with your own card, confirm Settings shows the plan as Active and
   a scan runs, then cancel and refund it from the Stripe dashboard.
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
   the pricing. `/monitoring` and any other page there that names Starter, Pro or credit packs
   must be changed to the single SecScan Unlimited plan ($19/month, unlimited scans,
   3 sites); that page is only true once step 6 has passed.

## Sales tax

Checkout does not collect sales tax or VAT. If you need to, turn on **Stripe
Tax** in the dashboard and add `automatic_tax: { enabled: true }` to both
checkout sessions in `routes/checkout.ts` — a decision for you and your
accountant, not a default.

## 4. Decide before switching monitoring to paid

Monitoring is free and unlimited for everyone today. It needs the SecScan Unlimited plan
when `MONITORING_REQUIRES_PLAN=true` is set on the **web** and **secscan** services, except
that an account with no plan keeps **one** free site (`FREE_MONITOR_SITES`, default 1; 0 turns
it off), rescanned no more often than weekly. The site limit applies when someone **adds** a
monitor: monitors an account already has keep running after the flag is set (still rescanned
no more often than weekly), but it cannot add another until it has a plan. Grandfathering
(below) keeps specific people on the normal grade-based cadence and a higher site limit.

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
