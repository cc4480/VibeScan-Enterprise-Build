/**
 * File a finding as a GitHub issue.
 *
 * An account names one repository and gives a fine-grained personal access token that can create issues in it. The token is
 * checked against GitHub when it is saved, stored encrypted, decrypted only to make a call, and never sent back to the
 * browser. SecScan's own GitHub App is read-only and is not used here: giving it write access would change what every
 * installer has approved, and an issue should be filed with the permission the account chose to grant.
 *
 * One issue per problem per site: filing the same finding again, from this report or a later scan, returns the issue that
 * already exists rather than a duplicate. Filing is bounded per account per day.
 */
import { and, eq, gte, inArray, sql } from "drizzle-orm";
import { db, githubIssueDestinationsTable, githubIssuesTable, reportsTable } from "@workspace/db";
import { decryptSecret, encryptSecret, isEncryptionConfigured } from "./crypto";
import { githubApi } from "./githubEndpoints";
import { APP_ORIGIN } from "./appOrigin";
import { findingKey, issueBody, issueTitle, parseRepo, ISSUE_LABELS, type IssueFinding } from "./githubIssueBody";

export const DAILY_ISSUES = 100;
const TIMEOUT_MS = 15_000;
/** GitHub's tokens: github_pat_… (fine-grained), ghp_… (classic), all URL-safe characters. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,255}$/;

export type Failure = { ok: false; status: 400 | 401 | 403 | 404 | 409 | 429 | 502 | 503; code: string; message: string };
const fail = (status: Failure["status"], code: string, message: string): Failure => ({ ok: false, status, code, message });

async function github(path: string, token: string, init: { method?: string; body?: unknown } = {}): Promise<{ status: number; json: unknown } | null> {
  try {
    const res = await fetch(`${githubApi()}${path}`, {
      method: init.method ?? "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SecScan",
        ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return { status: res.status, json: await res.json().catch(() => null) };
  } catch {
    return null;
  }
}

const rec = (v: unknown): Record<string, unknown> => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

// ── The destination ───────────────────────────────────────────────────────────

export type AutoSeverity = "critical" | "high" | "medium";
export const AUTO_SEVERITIES: readonly AutoSeverity[] = ["critical", "high", "medium"];

export async function getDestination(userId: string): Promise<{ repoFullName: string; autoFile: boolean; autoMinSeverity: AutoSeverity } | null> {
  const [row] = await db.select({
    repoFullName: githubIssueDestinationsTable.repoFullName,
    autoFile: githubIssueDestinationsTable.autoFile,
    autoMinSeverity: githubIssueDestinationsTable.autoMinSeverity,
  }).from(githubIssueDestinationsTable).where(eq(githubIssueDestinationsTable.userId, userId));
  return row ?? null;
}

/** Turn filing-by-itself on or off, and choose the lowest severity it files. False when no repository is connected. */
export async function setAutoFile(userId: string, enabled: boolean, minSeverity: AutoSeverity): Promise<boolean> {
  const rows = await db.update(githubIssueDestinationsTable)
    .set({ autoFile: enabled, autoMinSeverity: minSeverity })
    .where(eq(githubIssueDestinationsTable.userId, userId))
    .returning({ userId: githubIssueDestinationsTable.userId });
  return rows.length > 0;
}

export async function saveDestination(userId: string, repoInput: string, token: string): Promise<{ ok: true; repoFullName: string } | Failure> {
  const repo = parseRepo(repoInput);
  if (!repo) return fail(400, "bad_repo", "Enter the repository as owner/name, for example acme/website.");
  if (!TOKEN_SHAPE.test(token.trim())) return fail(400, "bad_token", "That does not look like a GitHub token. Create a fine-grained token and paste it whole.");
  if (!isEncryptionConfigured()) return fail(503, "no_encryption", "Storing a token is not available on this server right now.");

  const clean = token.trim();
  const res = await github(`/repos/${repo.owner}/${repo.repo}`, clean);
  if (!res) return fail(502, "github_unreachable", "GitHub could not be reached, so the token was not checked. Try again in a moment.");
  if (res.status === 401) return fail(401, "token_rejected", "GitHub rejected that token. It may be wrong, expired or revoked.");
  if (res.status === 404 || res.status === 403) {
    return fail(404, "repo_not_visible", `That token cannot see ${repo.fullName}. Check the name, and that the token was granted this repository.`);
  }
  if (res.status !== 200) return fail(502, "github_error", `GitHub answered ${res.status} when checking the repository.`);
  if (rec(res.json)["has_issues"] === false) return fail(409, "issues_disabled", `Issues are turned off on ${repo.fullName}. Turn them on in the repository's settings first.`);
  if (rec(res.json)["archived"] === true) return fail(409, "archived", `${repo.fullName} is archived, so issues cannot be created in it.`);

  const tokenEncrypted = encryptSecret(clean);
  // Pointing the account at a different repository switches filing-by-itself off: it was agreed for the old one.
  const sameRepo = (await getDestination(userId))?.repoFullName === repo.fullName;
  await db.insert(githubIssueDestinationsTable)
    .values({ userId, repoFullName: repo.fullName, tokenEncrypted })
    .onConflictDoUpdate({ target: githubIssueDestinationsTable.userId, set: { repoFullName: repo.fullName, tokenEncrypted, createdAt: new Date(), ...(sameRepo ? {} : { autoFile: false }) } });
  return { ok: true, repoFullName: repo.fullName };
}

export async function removeDestination(userId: string): Promise<void> {
  await db.delete(githubIssueDestinationsTable).where(eq(githubIssueDestinationsTable.userId, userId));
}

// ── Filing ────────────────────────────────────────────────────────────────────

const str = (v: unknown) => (typeof v === "string" ? v : "");

/** The finding with this id in a stored report, with the fields an issue needs. Scan-coverage notices are not findings. */
export function findingOf(data: unknown, findingId: string): IssueFinding | null {
  const vulns = Array.isArray(rec(data)["vulnerabilities"]) ? (rec(data)["vulnerabilities"] as unknown[]) : [];
  const hit = vulns.map(rec).find((v) => v["id"] === findingId && str(v["category"]) !== "Scan Coverage");
  if (!hit) return null;
  return {
    id: findingId, name: str(hit["name"]), severity: str(hit["severity"]) || "info", category: str(hit["category"]),
    description: str(hit["description"]), evidence: str(hit["evidence"]) || null, solution: str(hit["solution"]) || null,
    cweId: str(hit["cweId"]) || null, wstgId: str(hit["wstgId"]) || null,
  };
}

export interface FiledIssue { ok: true; created: boolean; issueNumber: number; issueUrl: string; repoFullName: string }

export async function fileIssue(input: { userId: string; reportId: string; findingId: string }): Promise<FiledIssue | Failure> {
  const [dest] = await db.select().from(githubIssueDestinationsTable).where(eq(githubIssueDestinationsTable.userId, input.userId));
  if (!dest) return fail(409, "no_destination", "Connect a GitHub repository first (Settings, GitHub issues).");

  const [report] = await db
    .select({ id: reportsTable.id, targetUrl: reportsTable.targetUrl, data: reportsTable.data })
    .from(reportsTable)
    .where(and(eq(reportsTable.id, input.reportId), eq(reportsTable.userId, input.userId)));
  const finding = report ? findingOf(report.data, input.findingId) : null;
  if (!report || !finding) return fail(404, "finding_not_found", "That finding was not found in your report.");

  const key = findingKey(report.targetUrl, finding.name);
  const repoFullName = dest.repoFullName;

  // Two requests for the same finding must not both reach GitHub, or it would file two issues. They take turns on a lock
  // keyed to the finding; the second then finds the first one's issue. The lock is released when the transaction ends, so
  // it cannot be left held, and the call to GitHub inside it is bounded by the request timeout.
  return db.transaction(async (tx): Promise<FiledIssue | Failure> => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`${input.userId}\n${repoFullName}\n${key}`}))`);

    const [existing] = await tx.select().from(githubIssuesTable).where(and(
      eq(githubIssuesTable.userId, input.userId), eq(githubIssuesTable.repoFullName, repoFullName), eq(githubIssuesTable.findingKey, key)));
    if (existing) return { ok: true, created: false, issueNumber: existing.issueNumber, issueUrl: existing.issueUrl, repoFullName };

    const since = new Date(Date.now() - 24 * 60 * 60_000);
    const [{ n } = { n: 0 }] = await tx.select({ n: sql<number>`count(*)::int` }).from(githubIssuesTable)
      .where(and(eq(githubIssuesTable.userId, input.userId), gte(githubIssuesTable.createdAt, since)));
    if (n >= DAILY_ISSUES) return fail(429, "daily_limit", `You have filed ${DAILY_ISSUES} issues in the last day. Try again tomorrow.`);

    let token: string;
    try { token = decryptSecret(dest.tokenEncrypted); } catch {
      return fail(409, "token_unreadable", "The saved GitHub token can no longer be read. Save it again in Settings.");
    }

    const res = await github(`/repos/${repoFullName}/issues`, token, {
      method: "POST",
      body: {
        title: issueTitle(finding, report.targetUrl),
        body: issueBody(finding, { targetUrl: report.targetUrl, reportUrl: `${APP_ORIGIN}/report/${report.id}` }),
        labels: ISSUE_LABELS,
      },
    });
    if (!res) return fail(502, "github_unreachable", "GitHub could not be reached. Nothing was filed; try again.");
    if (res.status === 401) return fail(401, "token_rejected", "GitHub rejected the saved token. It may have expired or been revoked: save a new one in Settings.");
    if (res.status === 403 || res.status === 404) {
      return fail(403, "no_permission", `The token cannot create issues in ${repoFullName}. Give it Issues: Read and write on that repository.`);
    }
    if (res.status === 410) return fail(409, "issues_disabled", `Issues are turned off on ${repoFullName}.`);
    const created = rec(res.json);
    const number = typeof created["number"] === "number" ? created["number"] : 0;
    const url = str(created["html_url"]);
    if (res.status !== 201 || !number || !url) return fail(502, "github_error", `GitHub answered ${res.status} and did not create the issue.`);

    await tx.insert(githubIssuesTable)
      .values({ userId: input.userId, repoFullName, findingKey: key, reportId: report.id, issueNumber: number, issueUrl: url })
      .onConflictDoNothing();
    return { ok: true, created: true, issueNumber: number, issueUrl: url, repoFullName };
  });
}

/** The issues already filed for the findings in this report, by finding id, for the destination currently connected. */
export async function issuesForReport(userId: string, reportId: string): Promise<Record<string, { issueNumber: number; issueUrl: string }>> {
  const dest = await getDestination(userId);
  if (!dest) return {};
  const [report] = await db.select({ targetUrl: reportsTable.targetUrl, data: reportsTable.data }).from(reportsTable)
    .where(and(eq(reportsTable.id, reportId), eq(reportsTable.userId, userId)));
  if (!report) return {};
  const vulns = Array.isArray(rec(report.data)["vulnerabilities"]) ? (rec(report.data)["vulnerabilities"] as unknown[]).map(rec) : [];
  const keyOf = new Map<string, string>();
  for (const v of vulns) if (str(v["id"]) && str(v["category"]) !== "Scan Coverage") keyOf.set(str(v["id"]), findingKey(report.targetUrl, str(v["name"])));
  if (keyOf.size === 0) return {};
  const rows = await db.select().from(githubIssuesTable).where(and(
    eq(githubIssuesTable.userId, userId), eq(githubIssuesTable.repoFullName, dest.repoFullName), inArray(githubIssuesTable.findingKey, [...new Set(keyOf.values())])));
  const byKey = new Map(rows.map((r) => [r.findingKey, r]));
  const out: Record<string, { issueNumber: number; issueUrl: string }> = {};
  for (const [id, key] of keyOf) { const r = byKey.get(key); if (r) out[id] = { issueNumber: r.issueNumber, issueUrl: r.issueUrl }; }
  return out;
}
