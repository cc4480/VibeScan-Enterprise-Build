# GitHub repository scan

Given a GitHub repository, SecScan reads its files through GitHub's API (no clone) and runs five checks. It is a static read of source: findings say what the files say, and every finding says it was read from the repository, not observed on the live site.

| Check | What it looks for |
|---|---|
| Repository secrets | The live scan's secret patterns plus a reader for config syntax, on `.env*`, compose files, credentials files, tfvars, Supabase migrations. |
| Supabase migrations | Public tables created and never given Row Level Security (applied in migration order, so a later `enable`/`drop` settles an earlier create); policies with condition `true` for `anon`/`public` (any write: high; read of a private-looking table: high; unknown name: info) or for every signed-in user. |
| CI and configuration | GitHub Actions `pull_request_target` that checks out the PR head; run steps interpolating attacker-controlled event text; `write-all`; echoed secrets. Dockerfile `ENV`/`ARG` with a literal credential. `supabase/config.toml` functions with `verify_jwt = false`. |
| Dangerous code patterns | A secret behind a client prefix (`VITE_`, `NEXT_PUBLIC_`...); `eval`/`new Function` on request data; SQL built by interpolating request data; CORS any-origin with credentials; TLS verification off; AI SDK allowed in the browser. Deliberately a short list of high-precision shapes, not a general static analyser. |
| Dependencies | Exact versions from `package-lock.json` (and exact pins in `package.json`) matched against OSV; direct dependencies first, 150 lookups per repository. |

## Bounds, and what a result means
At most 300 files, 1 MB each (5 MB for a lockfile), 25 MB in total, prioritised secrets, migrations, CI, manifests, then application code. Anything over a bound, any file that could not be downloaded, and a truncated file list produce the "GitHub source scan covered only part of the repository" note with the counts. A check with nothing to look at is recorded as such, not as passed. A repository that could not be read is "not tested", never clean.

## Access
- **Public repositories:** no credential is involved.
- **Private repositories:** through a GitHub App (`githubApp.ts`). The owner installs it and picks the repositories; it holds Contents: read and Metadata: read only. SecScan stores no user credential: it signs a short JWT with the App's private key (environment secret) and exchanges it for an hour-long installation token limited to the one repository and read-only contents, used in memory for that scan. The job carries the installation id, which is not a secret.
- **One-time setup (GitHub, Settings, Developer settings, GitHub Apps):** permissions as above, no webhook needed; then set `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` (PEM, newlines or `\n`), `GITHUB_APP_SLUG`.

## Not built yet
The installation flow in the product: a table mapping an account to its installation ids, the install-callback route and the repository picker in the UI, and passing the installation id through the scan job so the worker mints the token. `RunScanExtras.githubAccessToken` and `scanRepository(githubInstallationSource(...))` are the seam it plugs into. Also not covered: Supabase RLS review of dashboard-only changes (no migration records them), other lockfile formats (pnpm, yarn), and languages other than JavaScript/TypeScript for the code patterns.

## Telling the scanner a finding is accepted: `.secscanignore`

Put a `.secscanignore` file in the **root** of the repository. One rule per line; `#` starts a comment.

```
# a path or glob, gitignore-style: every finding whose files all match is left out
legacy/
scripts/seed.*
/docker-compose.dev.yml

# a rule name (a case-insensitive part of the finding's title), anywhere
rule: Container Runs as Root

# a rule name, only in matching files
rule: Hardcoded Password @ scripts/seed.*
```

The report always says what was suppressed: a "N findings suppressed by .secscanignore" note lists each rule and the findings it removed, so a suppression can be seen and reviewed. A note about the scan itself (such as "covered only part of the repository") is never suppressed. The file is read from the repository root only, and a finding that touches any file the rules do not cover stays.
