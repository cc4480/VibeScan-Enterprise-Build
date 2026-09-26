# Roadmap status

The 31 upgrades from the field report (2026-09-26). Decision on 2026-09-26: build all open items before launch, then run the full false-positive sweep, then launch. Payments stay off until then.

Rules for every item: its own commit; typecheck, tests, push; no file over 300 lines; every new check ships with a vulnerable case and a clean twin in `artifacts/vuln-fixture`; the check catalog (`checkCatalog*.ts`) and secscan.info `coverage.ts` stay in step.

Status: **done**, **partial**, **todo**.

| # | Upgrade | Status | Notes |
|---|---|---|---|
| U1 | Public head-to-head, rerunnable | todo | Needs the user's accounts on rival services and a throwaway host |
| U2 | Methodology, data handling, disclosure | done | secscan.info/security, security.txt |
| U3 | Make failed probes visible | done | Already built; shown live |
| U4 | Send less to the language model, provider choice | partial | Redaction and LLM_ENDPOINT done; no user-facing choice |
| U5 | Third-party script check that understands first-party CDNs | done | first-party CDNs and provider-updated scripts exempt; 11 to 4 flagged sites on the 20-site run |
| U6 | A public status page | todo | Needs the user's UptimeRobot page |
| U7 | GitHub Action, CLI and SARIF | **done** | deploy/cli (CLI + action.yml); SARIF at /v1/scans/:id/sarif. To publish the Action, copy deploy/cli to its own repo and tag v1 (needs the user) |
| U8 | Alert destinations and ticketing | todo | |
| U9 | Verify the fix | **done** | "Fixed this? Check it" on each finding: a free, limited (10 a day) re-scan judged against that one finding. Fixed only if its test ran again; otherwise "could not be re-checked". Full re-scan for now; a targeted single-test re-run would be faster (later) |
| U10 | Supabase and Firebase in depth | done | Supabase auth confirmation + storage file listing, Firebase storage listing (baasDepth.ts); tested with mocked responses and clean twins, not the live-host fixture (these hit supabase.co / googleapis.com) |
| U11 | Checks for AI features inside the app | done | passive only: provider called from browser, system prompt in bundle (aiFeatureProbe.ts, first-party JS only). No prompt-injection probing on purpose: model replies are not a stable signal |
| U12 | One defect, one finding | needs decision | merging conflicts with per-finding fixture/benchmark and changes grades |
| U13 | Fix prompts that know the platform | done | added hosted builders, Firebase, Vercel, Netlify to the existing five; prompts are model-written, so wording is steered not guaranteed |
| U14 | Easy two-account testing | partial | Works; setup still manual |
| U15 | Wider injection coverage | done | server-side template injection and CRLF header injection, each with clean twins; also fixed reflected XSS counting JSON/plain-text echoes. Not added: command/NoSQL/XXE injection (no confirmation that is stable enough to trust) |
| U16 | Reproduce steps for confirmable findings | done | curl replay only when evidence is a plain GET/HEAD/OPTIONS; nothing guessed |
| U17 | Faster first result | partial | Live results done; median time not published |
| U18 | Runtime-aware crawling for SPAs | partial | the rendered page's own fetch/XHR calls now feed API testing (apiRuntime.ts), verified with real Chromium on a fixture API no bundle string names. Not done: rendering each inner route in the browser; inner routes are still fetched raw |
| U19 | GraphQL and WebSocket depth | todo | |
| U20 | Evidence packs, trust page, white-label | todo | |
| U21 | Teams | todo | |
| U22 | A REST API | **done** | /api/v1, api-scope tokens, OpenAPI at /api/v1/openapi.json |
| U23 | Monitoring controls | todo | |
| U24 | Changes since the last scan | **done** | Report card, report email line, API (counts on status, full lists on the report). A finding is "fixed" only if its test ran again; otherwise "not re-checked" |
| U25 | Test the free tier | todo | Needs real traffic |
| U26 | One-click MCP sign-in with OAuth | **done** | OAuth 2.1: discovery, dynamic registration, PKCE S256, consent page, 1 h access and rotating refresh tokens with reuse detection, Connected apps in Settings. Run the real-database suites with --no-file-parallelism |
| U27 | More control frameworks | done | NIST SP 800-53 Rev. 5 and HIPAA 164.312 added in complianceExtra.ts; conservative, HIPAA only where a technical safeguard speaks to the weakness; CIS Controls and GDPR not added |
| U28 | Third-party proof of own security | todo | Needs an outside firm |
| U29 | Content from sources buyers trust | todo | |
| U30 | Brand and search collision | todo | User's decision |
| U31 | Directory presence | partial | Registry listed; Smithery, cursor.directory to do |
