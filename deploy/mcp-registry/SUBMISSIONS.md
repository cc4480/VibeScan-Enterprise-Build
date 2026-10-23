# Directory listings: copy to paste

Ready-made text for the directories that are not the official MCP Registry (that one is
`server.json` + `PUBLISH.md`). Each directory has its own form or file format, which changes;
check the current one when you submit. The facts below are the part that must stay true.

Directories still to do (needs the owner's account on each): **Smithery**, **cursor.directory**.
Others worth a look: Glama, mcp.so, PulseMCP.

## Facts (keep in step with secscan.info/ai-editors and routes/mcp.ts)

- Name: SecScan
- One line: Scan, monitor and fix a live web app from your editor: graded security reports with fix prompts.
- Endpoint: `https://secscan.us/api/mcp` (remote, streamable HTTP; no local install)
- Sign-in: OAuth 2.1 (consent screen, no token to copy) or a token starting `ssk_` from
  https://secscan.us/settings#ai-editors sent as `Authorization: Bearer ssk_...`
- Docs: https://secscan.info/ai-editors, https://secscan.info/developers
- Registry name: `us.secscan/secscan`
- Free: 3 scans every month per account
- Tools (12): scan_url, get_scan_status, get_report, list_recent_scans, list_verified_domains,
  start_domain_verification, check_domain_verification, get_account, list_monitors, add_monitor,
  monitor_scan_now, dismiss_finding

## Longer description

SecScan runs a black-box security scan of a web application you own or are authorised to test
and returns a graded report: what was tested, what was skipped, each finding with evidence and a
fix, and a fix prompt written for your editor. From Claude Code, Cursor or any MCP client you can
start a scan, wait for the result, work through the fixes, then rescan to confirm. Active tests
(injection, access control, SSRF) run only on domains you have verified you own.

## Do not claim

- A compliance certification or pass. Reports map findings to controls as evidence only.
- That a clean scan means a site is secure. The report says which tests ran and which did not.
