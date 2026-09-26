# SecScan CLI and GitHub Action

Scan a deployed URL from a terminal or CI job, and fail the build on findings.
One folder, three uses: the command line (`secscan.mjs`), a GitHub Action (`action.yml`),
and an npm package (`package.json`, not yet published).

You need a token whose scope is **API**: secscan.us → Settings → AI editors and API →
"Scripts and CI". Store it as a secret, never in a file.

## GitHub Action

```yaml
name: Security scan
on:
  deployment_status:
permissions:
  contents: read
  security-events: write   # only if you upload to code scanning
jobs:
  secscan:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: YOUR-ORG/secscan-action@v1
        with:
          url: ${{ github.event.deployment_status.target_url }}
          token: ${{ secrets.SECSCAN_TOKEN }}
          fail-on: high
          min-grade: C
          upload-sarif: "true"
```

To publish the Action, copy this folder to its own repository (`action.yml` must be at the
root) and tag it `v1`.

## Command line

```
export SECSCAN_TOKEN=ssk_...
node secscan.mjs scan https://staging.example.com --fail-on high --sarif secscan.sarif
```

Options: `--fail-on critical|high|medium|low|info|none` (default `high`), `--min-grade A..F`,
`--sarif <file>`, `--json <file>`, `--timeout <seconds>` (default 300), `--api <url>`.

| Exit code | Meaning |
|---|---|
| 0 | The scan finished and the build passes |
| 1 | The scan finished and the policy failed |
| 2 | Bad usage, or the scan failed or timed out |
| 3 | The token was refused, or the API could not be reached |

## What a pass means

A pass means the tests that ran found nothing at the level you set. It always prints how many
tests were **skipped**. Active tests (injection, access control, SSRF) run only on domains you have
verified, so a scan of an unverified preview URL is passive only. Verify the domain in Settings →
Domains, or treat the pass accordingly.

## SARIF

SecScan scans a running site, not source files, so results have no file or line: each is located
at the URL it was found at. GitHub shows them as alerts on the repository, not inline in a diff.
