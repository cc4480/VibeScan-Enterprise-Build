/**
 * CI and deployment configuration: GitHub Actions workflows, Dockerfiles, and the Supabase function config.
 *
 * What goes wrong here is not a leaked key but a door: a workflow that runs a pull request's code with the repository's
 * secrets, a shell step that interpolates an issue title, an image with a credential baked into a layer, an edge function
 * that skips the JWT check. Each rule is narrow on purpose, with the shape that makes it a flaw spelled out in the
 * finding, because a CI finding that cries wolf is switched off.
 */
import { repoFinding, type RepoFile, type RepoRef } from "./repoFinding";
import { isPlaceholderToken } from "./secretPlaceholders";
import { infraFindings, dockerHygieneFindings, actionsHygieneFindings, isInfraPath } from "./repoCheckInfra";
import { supabaseAuthConfigFindings } from "./repoCheckSupabaseExtra";
import type { ScanVulnerability } from "./scanner";

export const isWorkflowPath = (p: string) => /(?:^|\/)\.github\/workflows\/[\w.-]+\.ya?ml$/i.test(p);
export const isDockerfilePath = (p: string) => /(?:^|\/)(?:Dockerfile(?:\.[\w.-]+)?|[\w.-]+\.Dockerfile)$/.test(p);
export const isSupabaseConfigPath = (p: string) => /(?:^|\/)supabase\/config\.toml$/i.test(p);

/** Event-payload fields an outsider controls: a title, a body, a branch name, a commit message. */
const ATTACKER_CONTROLLED =
  /\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|pages)\.[\w.\[\]*-]*?(?:title|body|name|label|ref|message|email|login)|github\.event\.commits\.[\w.*\[\]-]*?(?:message|name|email)|github\.head_ref|github\.event\.workflow_run\.head_branch)\s*\}\}/i;

function workflowFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const text = f.content;

  // pull_request_target runs with the base repository's secrets and a write token. Checking out the PR's own code in
  // that context hands both to whoever opened the PR.
  if (/^\s*(?:on\s*:\s*)?\s*-?\s*pull_request_target\b|^\s*pull_request_target\s*:|\bon\s*:\s*\[[^\]]*pull_request_target/im.test(text) &&
      /uses\s*:\s*actions\/checkout[\s\S]{0,400}?ref\s*:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)/i.test(text)) {
    out.push(repoFinding({
      ref, path: f.path, name: "GitHub Actions Workflow Runs Pull-Request Code With Repository Secrets",
      severity: "high", category: "CI/CD Security", cweId: "CWE-94", cvssScore: 8.8, confidence: 80,
      description: "The workflow is triggered by pull_request_target, which runs with the base repository's secrets and a write-scoped token, and then checks out the pull request's own head. A pull request from a fork can change any script this workflow runs and read those secrets (the \"pwn request\" pattern).",
      solution: "Do not check out or run the pull request's code in a pull_request_target workflow. Use the pull_request trigger for builds and tests, or split the privileged step into a separate workflow_run job that only consumes artifacts.",
    }));
  }

  // Shell steps that interpolate an outsider-controlled string.
  const runBlocks = [...text.matchAll(/^(\s*)(?:-\s*)?run\s*:\s*(\|[-+]?\s*\n(?:\1\s+.*\n?)+|.*)$/gim)].map((m) => m[2] ?? "");
  const injected = runBlocks.find((b) => ATTACKER_CONTROLLED.test(b));
  if (injected) {
    const expr = ATTACKER_CONTROLLED.exec(injected)![0];
    out.push(repoFinding({
      ref, path: f.path, name: "GitHub Actions Shell Step Interpolates Attacker-Controlled Text",
      severity: "high", category: "CI/CD Security", cweId: "CWE-78", cvssScore: 8.1, confidence: 75,
      description: `A run: step puts ${expr} straight into a shell script. GitHub substitutes the value before the shell parses the line, so a title, branch name or message containing shell syntax runs as a command on the runner, with whatever secrets and token that job has.`,
      detail: `Expression: ${expr}`,
      solution: "Pass the value through an environment variable and use it quoted in the script: env: TITLE: ${{ github.event.issue.title }} then run: echo \"$TITLE\".",
    }));
  }

  if (/^\s*permissions\s*:\s*write-all\s*$/im.test(text)) {
    out.push(repoFinding({
      ref, path: f.path, name: "GitHub Actions Workflow Requests write-all Permissions",
      severity: "medium", category: "CI/CD Security", cweId: "CWE-250", cvssScore: 5.9, confidence: 80,
      description: "The workflow grants its token write access to every scope. A compromised step or third-party action can then push code, edit releases and change settings.",
      solution: "Set permissions: contents: read at the top and grant a write scope only to the job that needs it.",
    }));
  }

  // Printed to the log, not written to a file or piped to a tool: `echo "...${{ secrets.X }}" > ~/.npmrc` is how a token is handed over.
  const printsSecret = text.split(/\r?\n/).some((line) => {
    const m = /^\s*(?:-\s*)?run\s*:\s*.*\b(?:echo|printf|cat)\b[^\n]*?(\$\{\{\s*secrets\.[\w-]+\s*\}\})/i.exec(line);
    return m !== null && !/[>|]/.test(line.slice(m.index + m[0].length));
  });
  if (printsSecret && !/::add-mask::/.test(text)) {
    out.push(repoFinding({
      ref, path: f.path, name: "GitHub Actions Step Prints a Secret",
      severity: "medium", category: "CI/CD Security", cweId: "CWE-532", cvssScore: 5.5, confidence: 60,
      description: "A run: step echoes a ${{ secrets.* }} value. GitHub masks exact matches in logs, but not transformed ones (base64, split or reversed), and the log of a public repository is public.",
      solution: "Never print a secret. Pass it to the tool that needs it through env: and let that tool read it.",
    }));
  }
  return out;
}

function dockerFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  for (const line of f.content.split(/\r?\n/)) {
    const m = /^\s*(ENV|ARG)\s+([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*)\s*[= ]\s*["']?([^\s"'$][^\s"']{7,})/i.exec(line);
    if (!m) continue;
    const value = m[3]!;
    if (isPlaceholderToken(value) || /^(?:changeme|change-me|your[-_]|example|placeholder|todo|dummy|test|none|null|false|true)/i.test(value)) continue;
    out.push(repoFinding({
      ref, path: f.path, name: "Dockerfile Bakes a Credential Into the Image",
      severity: "high", category: "Exposed Secrets / Credentials", cweId: "CWE-798", cvssScore: 7.5, confidence: 70,
      description: `The Dockerfile sets ${m[1]!.toUpperCase()} ${m[2]} to a literal value. ENV and ARG values are stored in the image's layers and metadata (docker history shows them), so anyone who can pull the image, or read this repository, has the credential.`,
      detail: `Line: ${m[1]!.toUpperCase()} ${m[2]} = (value hidden, ${value.length} characters)`,
      solution: "Pass the secret at run time (docker run -e, orchestrator secrets) or use a BuildKit secret mount for build steps, and rotate this value.",
    }));
    break; // one per file is enough to act on
  }
  return out;
}

/** [functions.name] sections of supabase/config.toml with verify_jwt = false. */
export function functionsWithoutJwt(toml: string): string[] {
  const names: string[] = [];
  let current: string | null = null;
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    const sec = /^\[functions\.([\w-]+)\]$/.exec(line);
    if (sec) { current = sec[1]!; continue; }
    if (line.startsWith("[")) { current = null; continue; }
    if (current && /^verify_jwt\s*=\s*false$/i.test(line)) names.push(current);
  }
  return names;
}

/** `supabase/functions/<name>/index.ts` (or .js, .mjs): the code of an edge function. */
export const isFunctionCodePath = (p: string) => /(?:^|\/)supabase\/functions\/[\w-]+\/index\.[mc]?[jt]sx?$/i.test(p);

const withoutComments = (code: string) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'])\/\/[^\n]*/g, "$1");

/**
 * The function checks who is calling: a webhook signature, an HMAC compared in constant time, or the caller's own JWT
 * resolved to a user. Looked for in code with the comments taken out, so "there is no signature check" does not count.
 */
export function authenticatesCaller(code: string): boolean {
  return /constructEvent(?:Async)?\s*\(|webhooks\s*\.\s*verify|verifyWebhook|\bsvix\b|timingSafeEqual|createHmac|\bhmac\b|x-hub-signature|stripe-signature|x-signature|\.auth\s*\.\s*getUser\s*\(|\bjwt\s*\.\s*verify|jwtVerify|verifyJwt/i
    .test(withoutComments(code));
}

const WEBHOOK_NAME = /webhook|hook|stripe|paddle|clerk|svix|github|polar|lemon/i;

/** supabase/config.toml: functions with verify_jwt = false, judged by what their own code does where it was read. */
function supabaseConfigFindings(f: RepoFile, ref: RepoRef, files: RepoFile[]): ScanVulnerability[] {
  const names = functionsWithoutJwt(f.content);
  if (names.length === 0) return [];
  const root = f.path.replace(/supabase\/config\.toml$/i, "");
  const codeOf = (n: string) => files.find((x) => isFunctionCodePath(x.path) && x.path.toLowerCase().startsWith(`${root}supabase/functions/${n}/index.`.toLowerCase()));
  const authenticated: string[] = [];
  const unsignedWebhooks: string[] = [];
  const open: string[] = [];
  for (const n of names) {
    const code = codeOf(n);
    if (code && authenticatesCaller(code.content)) authenticated.push(n);
    else if (code && WEBHOOK_NAME.test(n)) unsignedWebhooks.push(n);
    else open.push(n);
  }
  const out: ScanVulnerability[] = [];
  if (unsignedWebhooks.length > 0) {
    out.push(repoFinding({
      ref, path: f.path, name: "Webhook Edge Function Accepts Unsigned Requests",
      severity: "high", category: "Broken Authentication", cweId: "CWE-345", cvssScore: 8.1, confidence: 70, wstgId: "WSTG-ATHN-04",
      description: `${unsignedWebhooks.join(", ")} ${unsignedWebhooks.length === 1 ? "is a webhook endpoint" : "are webhook endpoints"} with verify_jwt = false, and its code does not verify the sender's signature. Anyone who can reach the URL can send a forged event (a payment marked paid, a user marked subscribed) and the function acts on it.`,
      detail: `Functions: ${unsignedWebhooks.join(", ")}\nNo signature check found in: ${unsignedWebhooks.map((n) => `supabase/functions/${n}/index.ts`).join(", ")}`,
      solution: "Verify the provider's signature before reading the body: for Stripe, stripe.webhooks.constructEventAsync(rawBody, req.headers.get('Stripe-Signature'), webhookSecret), and refuse the request when it throws.",
    }));
  }
  if (open.length > 0) {
    out.push(repoFinding({
      ref, path: f.path, name: "Supabase Edge Functions Configured Without JWT Verification",
      severity: "medium", category: "Broken Access Control", cweId: "CWE-306", cvssScore: 6.5, confidence: 55, wstgId: "WSTG-ATHZ-01",
      description: `${open.length} edge function(s) have verify_jwt = false and no check of the caller was found in their code: ${open.join(", ")}. Supabase then lets anyone call them without signing in. That is intended for webhooks that authenticate another way (a Stripe signature, a shared secret), and not for functions that read or change a user's data.`,
      detail: `Functions: ${open.join(", ")}${authenticated.length ? `\nChecked their own caller in code (not listed above): ${authenticated.join(", ")}` : ""}`,
      solution: "Remove verify_jwt = false unless the function authenticates the caller itself. For webhooks, verify the provider's signature in the function and keep verify_jwt = false only there; for the rest, leave JWT verification on and resolve the user with supabase.auth.getUser().",
    }));
  }
  return out;
}

export function ciConfigFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  for (const f of files) {
    if (isWorkflowPath(f.path)) out.push(...workflowFindings(f, ref), ...actionsHygieneFindings(f, ref));
    else if (isDockerfilePath(f.path)) out.push(...dockerFindings(f, ref), ...dockerHygieneFindings(f, ref));
    else if (isSupabaseConfigPath(f.path)) out.push(...supabaseConfigFindings(f, ref, files), ...supabaseAuthConfigFindings(f, ref));
    else if (isInfraPath(f.path)) out.push(...infraFindings(f, ref));
  }
  return out;
}
