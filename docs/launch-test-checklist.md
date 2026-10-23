# Live test checklist: SecScan (secscan.us) and Seclayer (seclayer.app)

Run this after the databases are wiped and Railway billing is paid. Use ONE email address you can read,
and a domain you own for the scan tests. Tick each box only when you saw the "Correct" result yourself.
Stripe stays off throughout. Both apps are in free mode, so scans cost nothing.

Notation: [ ] = not done. If a step fails, stop there and note the exact message; do not skip ahead.

---------------------------------------------------------------------------------------------------
## 0. Before you start (5 min)

- [ ] Railway dashboard: no "past due" banner; every service in both projects shows online.
- [ ] https://secscan.us/api/healthz  -> {"status":"ok"}
- [ ] https://seclayer.app/api/system/health  -> {"status":"Online", ...}
- [ ] Databases wiped (run the wipe script; keep the backup file it writes in your home folder).
- [ ] Seclayer variables present in Railway (names only): ENCRYPTION_KEY, ORIGIN_AUTH_SECRET, DATABASE_URL, RESEND_API_KEY.
- [ ] SecScan variables present: ENCRYPTION_KEY, APP_ORIGIN (https://secscan.us), RESEND_API_KEY, DATABASE_URL.

---------------------------------------------------------------------------------------------------
## 1. Sign-up and sign-in (do this on EACH app)

| # | Step | Correct |
|---|------|---------|
| 1.1 | Register with your email and a password | The page asks for a 6-digit code (no error like "Could not send your code") |
| 1.2 | Open your inbox | The email arrives within about a minute, from your sending domain, not in spam |
| 1.3 | Enter the code | You land signed in |
| 1.4 | Reload the page | Still signed in |
| 1.5 | Sign out, sign back in | A new code is emailed; the old code no longer works |
| 1.6 | Enter a wrong code 6 times | You are locked out of that code ("Too many attempts"), not let in |
| 1.7 | Use "forgot password" | A reset email arrives; the new password works; the old one does not |
| 1.8 | Seclayer only: Google sign-in button | Signs you in, and the account shows the same email |

If 1.1 fails with "Could not send your code": the Resend key, sending domain or sender address is wrong. Check Railway logs for the Resend error.

---------------------------------------------------------------------------------------------------
## 2. A scan, start to finish (EACH app)

Use a site you own. Do not scan anything you do not own or have permission to test.

| # | Step | Correct |
|---|------|---------|
| 2.1 | Start a scan of your site | Status moves queued -> scanning -> complete; progress is shown |
| 2.2 | Wait for it to finish | A report appears with a score and findings; no endless spinner |
| 2.3 | Open the finding detail | Evidence and a fix suggestion are shown |
| 2.4 | Go to your scan history | The scan is listed with the right URL, date and score |
| 2.5 | Reload the report URL in a fresh tab while signed in | Same report |
| 2.6 | Open that report URL in a private window (signed out) | You are refused / asked to sign in. You must NOT see it |
| 2.7 | Try to scan http://169.254.169.254/ and http://127.0.0.1/ | Refused with a message that it is a private/local address |
| 2.8 | Seclayer: add a login header (Authorization) when scanning | The scan runs; the header is never shown again in the UI (only "a header is set") |
| 2.9 | Start a scan and cancel it | Status becomes canceled and stops running |
| 2.10 | Scan a site that is down or does not exist | Fails cleanly with an error message, not a hang |

---------------------------------------------------------------------------------------------------
## 3. Domain verification and active probes (EACH app)

Active (attack-style) probes and nmap must only run against domains you have proven you own.

| # | Step | Correct |
|---|------|---------|
| 3.1 | Scan a domain you have NOT verified | Passive checks only; the report says active probes were skipped |
| 3.2 | Start verification for your domain | You are given a token plus two options |
| 3.3 | Option A: add a DNS TXT record. Seclayer: _seclayer-challenge.<domain>. SecScan: _secscan-challenge.<domain> | Check succeeds once DNS has propagated (can take minutes) |
| 3.4 | Option B: publish the token at /.well-known/seclayer-verification.txt (Seclayer) or /.well-known/secscan-verification.txt (SecScan) over HTTPS | Check succeeds |
| 3.5 | Scan the verified domain | Active probes now run; report has more findings |
| 3.6 | Seclayer only: run an nmap scan on a domain verified by DNS only | REFUSED: nmap needs the well-known file to be live. Publish the file, retry, it runs |
| 3.7 | Seclayer only: remove the well-known file, run nmap again | Refused again (proof is re-checked each time) |
| 3.8 | Click verify 21+ times in a minute | Rate limited (HTTP 429) |

---------------------------------------------------------------------------------------------------
## 4. API access and MCP (Seclayer)

| # | Step | Correct |
|---|------|---------|
| 4.1 | Create an API key in your account | The key is shown ONCE; reloading shows only a prefix |
| 4.2 | curl -H "X-API-Key: <key>" https://seclayer.app/api/mcp/scans | Your scans list (empty at first) |
| 4.3 | Same request with the key in the URL (?apiKey=...) | Refused with a message telling you to use the header |
| 4.4 | Run a scan with the key via POST /api/mcp/scan | Returns a report. If it runs past ~80 seconds you get HTTP 202 with a scanId and pollUrl instead; polling pollUrl returns the report when done |
| 4.5 | Fire 6+ scans with the one key at once | The extra ones are refused with 429 (per-user in-flight cap), and no credit is lost |
| 4.6 | Install @seclayer/mcp in an editor and call the scan tool | Returns findings; for a slow scan it waits instead of erroring |
| 4.7 | Revoke the key, call again | 401 |

SecScan: sign in, create an API token in settings, and repeat 4.2 / 4.7 against its API docs.

---------------------------------------------------------------------------------------------------
## 5. Records are being kept correctly (the thing you asked about)

After sections 1 to 4, confirm the data really was recorded. In the Railway Postgres "Data" tab (or psql):

- [ ] users: exactly one row per account you registered, with the right email. No duplicate rows.
- [ ] sessions: one live row per signed-in device; signing out removes it.
- [ ] scans: one row per scan you ran, with the right target, status complete/failed/canceled, and a completed time.
- [ ] Seclayer scans: authHeader column starts with "enc.v1." (sealed) and is NOT readable text.
- [ ] domain_verifications: your domain, verified, with the method (dns or file).
- [ ] api_keys (Seclayer): hashed key only, never the key itself.
- [ ] Seclayer transactions: no purchase rows (Stripe is off). No negative or unexplained credit changes.
- [ ] A failed scan did not leave a scan stuck in "scanning" more than a few minutes.

---------------------------------------------------------------------------------------------------
## 6. Across both apps

- [ ] Open the site from a phone: sign in and view a report; layout is usable.
- [ ] Legal pages load (privacy, terms) and the contact/support address works.
- [ ] A scan emails you when finished, if you turned notifications on (check spam).
- [ ] Railway logs for both apps show no repeating errors while you do all of the above.
- [ ] Redeploy once from the Railway dashboard and confirm the site comes back healthy with no data loss
      (you stay signed in, your scans are still there).
- [ ] Railway billing: paid, no banner.

---------------------------------------------------------------------------------------------------
## 7. Last: before you turn Stripe on (not now)

Do these in Stripe TEST mode first, never production keys on the live services:

- [ ] Webhook delivers four events: checkout.session.completed, checkout.session.async_payment_succeeded, charge.refunded, charge.dispute.created.
- [ ] Buy a credit pack with test card 4242 4242 4242 4242: credits increase once, and exactly once if the webhook is sent twice.
- [ ] Refund it in the Stripe dashboard: credits are taken back once.
- [ ] Set FREE_MODE=false only after the above, and confirm a scan then costs one credit and a failed scan refunds it.
- [ ] Add the real keys to Railway, redeploy, check the boot log for the Stripe-enabled message.

---------------------------------------------------------------------------------------------------
## If something fails

Write down: which step number, what you saw (exact error text), the time. Then paste that to me. For the
server side I can read the Railway logs for that minute once the CLI is allowed to run again.
