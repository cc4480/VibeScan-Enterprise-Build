# SecScan build report, 2026-09-26

What was added since the roadmap decision ("build all open items, then the false-positive sweep, then launch"). Payments stay OFF. Everything below is pushed: `VibeScan-Enterprise-Build` on `master`, `secscan-info` on `main`.

Verification at the end of the run: API tests 1615 pass (104 skipped, need a database), frontend tests 131 pass, typechecks clean, vulnerable-app check 80/80 with the clean-twin check passing.

## Status of the 31 upgrades

| Status | Items |
|---|---|
| Done | U2, U3, U4, U5, U7, U9, U10, U11, U13, U14, U15, U16, U22, U24, U26, U27 |
| Partial | U17, U18, U19, U23, U31 |
| Needs your decision | U12 |
| Not started (need you or a large build) | U1, U6, U8, U20, U21, U25, U28, U29, U30 |

## Scanner: new checks (check catalog 131 to 140)

| Check | Severity | How it is confirmed | Clean twin |
|---|---|---|---|
| Missing SRI, rewritten (U5) | Medium | skips a site's own CDNs and scripts that must not have SRI (Stripe.js, GTM, reCAPTCHA, consent managers) | own-CDN and provider cases |
| Supabase email confirmation disabled | Low | server states `mailer_autoconfirm: true` and sign-up open | confirmation on |
| Supabase storage files listable | Medium | a file name is returned by the anon key | denied or empty bucket |
| Firebase storage files listable | High | a file name is returned unauthenticated | 403 |
| AI provider called from the browser | Low | `dangerouslyAllowBrowser` or a fetch/baseURL aimed at a provider, in first-party JS only | call to own `/api/chat` |
| AI system prompt in client code | Low | long `role:"system"` literal in the bundle | short or server-built prompt |
| Server-side template injection | Critical | arithmetic between random tokens comes back computed | echo as text |
| HTTP header (CRLF) injection | Medium | an injected header with a random name appears | encoded value |
| GraphQL query batching enabled | Low | array of 3 operations returns 3 results | server refuses arrays |
| GraphQL IDE exposed | Medium | the page is GraphiQL, Playground, Sandbox or Altair itself | SPA shell |

Engine changes:
- Reflected XSS now requires an HTML response. Before, a payload echoed in JSON or plain text counted. The vulnerable test app was doing this itself.
- The rendered page's own fetch/XHR calls now feed API testing (`apiRuntime.ts`). Method, URL and JSON body key names only; never values. Verified with real Chromium on an API no bundle string names.
- Compliance mapping gained NIST SP 800-53 Rev. 5 and the HIPAA Security Rule technical safeguards (`complianceExtra.ts`), plus CWE-1336, 113 and 489.
- New category "AI Feature Security" (same colour family as secrets).

## Product features

- **REST API** at `/api/v1` with OpenAPI, SARIF export, API-scope tokens (U22, U7). CLI and GitHub Action in `deploy/cli` (repo for the Action not yet published).
- **OAuth 2.1 for MCP** (U26): discovery, dynamic registration, PKCE S256, consent page, rotating refresh tokens, Connected apps in Settings.
- **Changes since your last scan** (U24) and **Verify the fix** (U9, free, 10 a day).
- **Reproduce steps** (U16): `curl` replay under evidence, only for a plain GET, HEAD or OPTIONS.
- **Platform-aware fix prompts** (U13): added Shopify/Wix/Squarespace/Webflow, Firebase, Vercel, Netlify to Lovable, Bolt, Next.js, WordPress, Supabase.
- **Second account can sign in with a form** (U14), reusing the first account's sign-in page.
- **Pause and resume a monitored site** (U23): skips every scheduled job; nothing deleted. Migration 0021.
- **AI analysis switch** (U4): Settings, Privacy. Off means findings are not sent to the AI provider; the report says the analysis is off. Migration 0022.
- **Live scan terminal, per-check colours, grade halo**, and the itemised check catalog (earlier in this run).
- **Billing hardening**: duplicate-subscription guard, Stripe replay script, tests updated.

## secscan.info

New `/developers` page (REST API, CLI, OAuth, what is not yet published). Updated coverage (140 checks, new modules), reports (scan diff, fix check, platform prompts, frameworks, AI switch), monitoring (pausing), AI editors, false-positives (SRI and XSS fixes), footer.

## Not done, and why

- **U8 ticketing**: needs your GitHub/Jira/Linear credentials stored securely.
- **U20 evidence packs, white-label; U21 teams**: large multi-tenant builds; not safe to rush.
- **U17**: no measured median scan time to publish.
- **U18**: inner routes still fetched raw, not rendered.
- **U19 WebSocket**: an open handshake is legitimate on many public sites, so a finding would not be trustworthy.
- **U23**: no frequency choice or quiet hours.
- **U12**: merging findings changes grades and conflicts with the per-finding benchmark; your call.
- **U1, U6, U25, U28, U29, U30, and submitting U31**: need your accounts, an outside firm, or decisions.

## Caveats you should know

- Supabase/Firebase and AI-in-client checks are tested with mocked responses or a fixture, not against live hosts.
- The U4 worker skip path has no automated test; the setting, route and database are tested.
- I did not run the produced `curl` commands against live targets.
- Two mistakes fixed along the way: a syntax error pushed to secscan.info (twice, broken builds for minutes, live site unaffected) and two dev log files committed, then untracked.
- Deploying runs migrations 0021 and 0022 on boot (add a column each).

## Still before launch

1. Full false-positive sweep (hand-check new-check findings on the 20 sites; clean twins exist for the new checks).
2. Go-live: restricted Stripe live key and webhook secret, Railway variables (`MONITORING_REQUIRES_PLAN=true` on both services), DB backup via `~/secscan-backup.ps1`.
3. Reminders: remove `SIGNUP_LIMIT_PER_NETWORK` from Railway web; confirm security@secscan.us; publish the GitHub Action repo; tell the Seclayer agent to trim `/api/system/health`; check Bing Webmaster Tools; decide the brand-collision plan (U30).
