# Live check on secscan.us (about 15 minutes)

Sign in at https://secscan.us.

## 1. Report branding (2 min)
1. Settings > Report branding: enter a business name, Save.
2. Open any report, download the PDF. Cover and footer say "Prepared by <name>", and the file name starts with the name.
3. Share the report, open the link signed out: footer shows the name.
4. Turn the SecScan credit off: shared page drops "Scan your own site".
5. Try a name like `http://x.com`: it must be refused.

## 2. Linear (5 min, needs a Linear API key and a team key such as ENG)
1. Settings > Linear and Jira > Linear: paste key and team key, Save.
2. Open a report with findings, click the Linear button on a finding. An issue appears in Linear and the button turns into a link.
3. Click it again: no duplicate.

## 3. Jira (5 min, needs *.atlassian.net site, email, API token, project key)
1. Settings > Linear and Jira > Jira: fill in, Save.
2. File a finding as a Jira ticket. Check it in Jira (priority, description).
3. If Jira rejects it, note the exact error text shown.

## 4. Automatic filing (needs a monitored site)
1. Settings > Linear and Jira: turn on automatic filing for a provider.
2. Wait for a monitor rescan that finds a new regression. A ticket should appear without a click.

## 5. Not live yet
Teammates: postponed, not part of this pass.

Paying the $19: pricing page still says "Purchasing isn't live yet". Production has STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET set; checkout needs turning on.

Report back anything that fails, with the exact text on screen.
