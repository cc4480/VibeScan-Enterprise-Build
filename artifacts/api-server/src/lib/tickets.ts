/**
 * File a finding as a Linear issue or a Jira ticket.
 *
 * The same shape as GitHub issues (lib/githubIssues.ts): an account names where tickets go and gives a credential that can
 * create them there. The credential is checked against the provider when it is saved, stored encrypted, decrypted only to
 * make a call, and never sent back to the browser. One ticket per problem per site per destination: filing the same finding
 * again, from this report or a later scan, returns the ticket that already exists. Filing is bounded per account per day.
 *
 * Linear: an API key and a team key (ENG). Jira Cloud: the site (acme.atlassian.net), the email the API token belongs to, the
 * token, a project key and an issue type.
 */
import { and, eq, gte, inArray, sql } from "drizzle-orm";
import { db, reportsTable, ticketDestinationsTable, ticketsTable } from "@workspace/db";
import { decryptSecret, encryptSecret, isEncryptionConfigured } from "./crypto";
import { APP_ORIGIN } from "./appOrigin";
import { findingKey, issueTitle, ISSUE_LABELS } from "./githubIssueBody";
import { findingOf } from "./githubIssues";
import { linearApi, jiraOrigin, parseJiraSite } from "./ticketEndpoints";
import { jiraDescription, jiraPriority, linearDescription, linearPriority } from "./ticketBody";

export const DAILY_TICKETS = 100;
const TIMEOUT_MS = 15_000;

export type Provider = "linear" | "jira";
export const PROVIDERS: readonly Provider[] = ["linear", "jira"];
export type AutoSeverity = "critical" | "high" | "medium";
export const AUTO_SEVERITIES: readonly AutoSeverity[] = ["critical", "high", "medium"];

const NAME: Record<Provider, string> = { linear: "Linear", jira: "Jira" };

export type Failure = { ok: false; status: 400 | 401 | 403 | 404 | 409 | 429 | 502 | 503; code: string; message: string };
const fail = (status: Failure["status"], code: string, message: string): Failure => ({ ok: false, status, code, message });

const rec = (v: unknown): Record<string, unknown> => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown) => (typeof v === "string" ? v : "");

async function call(url: string, headers: Record<string, string>, init: { method?: string; body?: unknown } = {}): Promise<{ status: number; json: unknown } | null> {
  try {
    const res = await fetch(url, {
      method: init.method ?? "GET",
      headers: { Accept: "application/json", "User-Agent": "SecScan", ...headers, ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}) },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "error", // the credential goes to the one address it was given for, never on to another
    });
    return { status: res.status, json: await res.json().catch(() => null) };
  } catch {
    return null;
  }
}

// ── Linear ────────────────────────────────────────────────────────────────────

/** A Linear API key is sent as is, without "Bearer" (that is for OAuth tokens). */
async function linear(key: string, query: string, variables: Record<string, unknown>) {
  const res = await call(`${linearApi()}/graphql`, { Authorization: key }, { method: "POST", body: { query, variables } });
  if (!res) return null;
  const errors = Array.isArray(rec(res.json)["errors"]) ? (rec(res.json)["errors"] as unknown[]).map(rec) : [];
  const authFailed = res.status === 401 || errors.some((e) => /authentication/i.test(str(rec(e["extensions"])["type"])) || /authentication/i.test(str(e["message"])));
  return { status: res.status, data: rec(rec(res.json)["data"]), errors, authFailed };
}

const LINEAR_KEY_SHAPE = /^[A-Za-z0-9_-]{20,255}$/;
const LINEAR_TEAM = /^[A-Za-z][A-Za-z0-9]{0,9}$/;

// ── Jira ──────────────────────────────────────────────────────────────────────

const JIRA_PROJECT = /^[A-Z][A-Z0-9_]{1,9}$/;
const JIRA_TOKEN_SHAPE = /^[\x21-\x7e]{10,300}$/;
const JIRA_EMAIL = /^[^\s@]{1,100}@[^\s@]{1,200}$/;
const DEFAULT_ISSUE_TYPE = "Task";

const jiraAuth = (email: string, token: string) => ({ Authorization: `Basic ${Buffer.from(`${email}:${token}`).toString("base64")}` });

// ── The destination ───────────────────────────────────────────────────────────

export interface Destination {
  provider: Provider;
  /** The Linear team key or the Jira project key. */
  target: string;
  site: string | null;
  accountEmail: string | null;
  issueType: string | null;
  autoFile: boolean;
  autoMinSeverity: AutoSeverity;
}

const publicColumns = {
  provider: ticketDestinationsTable.provider, target: ticketDestinationsTable.target, site: ticketDestinationsTable.site,
  accountEmail: ticketDestinationsTable.accountEmail, issueType: ticketDestinationsTable.issueType,
  autoFile: ticketDestinationsTable.autoFile, autoMinSeverity: ticketDestinationsTable.autoMinSeverity,
};

/** What an account has connected. The credential is not in this. */
export async function getDestinations(userId: string): Promise<Destination[]> {
  return db.select(publicColumns).from(ticketDestinationsTable).where(eq(ticketDestinationsTable.userId, userId));
}

export async function getDestination(userId: string, provider: Provider): Promise<Destination | null> {
  const [row] = await db.select(publicColumns).from(ticketDestinationsTable)
    .where(and(eq(ticketDestinationsTable.userId, userId), eq(ticketDestinationsTable.provider, provider)));
  return row ?? null;
}

/** Where tickets for this destination live, for the one-per-problem rule: pointing the account elsewhere starts afresh. */
export const placeOf = (d: { provider: Provider; target: string; site: string | null }): string => (d.provider === "jira" ? `${d.site}/${d.target}` : d.target);

export async function setAutoFile(userId: string, provider: Provider, enabled: boolean, minSeverity: AutoSeverity): Promise<boolean> {
  const rows = await db.update(ticketDestinationsTable).set({ autoFile: enabled, autoMinSeverity: minSeverity })
    .where(and(eq(ticketDestinationsTable.userId, userId), eq(ticketDestinationsTable.provider, provider)))
    .returning({ userId: ticketDestinationsTable.userId });
  return rows.length > 0;
}

export async function removeDestination(userId: string, provider: Provider): Promise<void> {
  await db.delete(ticketDestinationsTable).where(and(eq(ticketDestinationsTable.userId, userId), eq(ticketDestinationsTable.provider, provider)));
}

export type SaveInput =
  | { provider: "linear"; team: string; apiKey: string }
  | { provider: "jira"; site: string; email: string; token: string; project: string; issueType?: string };

export async function saveDestination(userId: string, input: SaveInput): Promise<{ ok: true; target: string } | Failure> {
  if (!isEncryptionConfigured()) return fail(503, "no_encryption", "Storing a credential is not available on this server right now.");
  const before = await getDestination(userId, input.provider);

  if (input.provider === "linear") {
    const team = input.team.trim().toUpperCase();
    const apiKey = input.apiKey.trim();
    if (!LINEAR_TEAM.test(team)) return fail(400, "bad_team", "Enter the team key as it appears in your issue numbers, for example ENG.");
    if (!LINEAR_KEY_SHAPE.test(apiKey)) return fail(400, "bad_token", "That does not look like a Linear API key. Create a personal API key in Linear and paste it whole.");
    const res = await linear(apiKey, "query($key: String!) { teams(filter: { key: { eq: $key } }) { nodes { id key } } }", { key: team });
    if (!res) return fail(502, "linear_unreachable", "Linear could not be reached, so the key was not checked. Try again in a moment.");
    if (res.authFailed) return fail(401, "token_rejected", "Linear rejected that key. It may be wrong or revoked.");
    if (res.errors.length > 0 || res.status !== 200) return fail(502, "linear_error", `Linear answered ${res.status} when checking the team.`);
    const nodes = Array.isArray(rec(res.data["teams"])["nodes"]) ? (rec(res.data["teams"])["nodes"] as unknown[]).map(rec) : [];
    const id = str(nodes[0]?.["id"]);
    if (!id) return fail(404, "team_not_visible", `That key cannot see a Linear team called ${team}. Check the team key.`);

    const sameTeam = before?.target === team;
    await db.insert(ticketDestinationsTable)
      .values({ userId, provider: "linear", target: team, externalId: id, credentialEncrypted: encryptSecret(apiKey) })
      .onConflictDoUpdate({
        target: [ticketDestinationsTable.userId, ticketDestinationsTable.provider],
        set: { target: team, externalId: id, credentialEncrypted: encryptSecret(apiKey), createdAt: new Date(), ...(sameTeam ? {} : { autoFile: false }) },
      });
    return { ok: true, target: team };
  }

  const site = parseJiraSite(input.site);
  const project = input.project.trim().toUpperCase();
  const email = input.email.trim();
  const token = input.token.trim();
  const issueType = input.issueType?.trim() || DEFAULT_ISSUE_TYPE;
  if (!site) return fail(400, "bad_site", "Enter your Jira Cloud site, for example acme.atlassian.net.");
  if (!JIRA_EMAIL.test(email)) return fail(400, "bad_email", "Enter the email address of the Atlassian account the token belongs to.");
  if (!JIRA_TOKEN_SHAPE.test(token)) return fail(400, "bad_token", "That does not look like an Atlassian API token. Create one and paste it whole.");
  if (!JIRA_PROJECT.test(project)) return fail(400, "bad_project", "Enter the project key as it appears in your ticket numbers, for example SEC.");
  if (issueType.length > 60 || /[\u0000-\u001f]/.test(issueType)) return fail(400, "bad_issue_type", "That issue type name is not valid.");

  const res = await call(`${jiraOrigin(site)}/rest/api/3/project/${project}`, jiraAuth(email, token));
  if (!res) return fail(502, "jira_unreachable", "Jira could not be reached, so the token was not checked. Try again in a moment.");
  if (res.status === 401) return fail(401, "token_rejected", "Jira rejected that email and token. Check both, and that the token has not been revoked.");
  if (res.status === 404 || res.status === 403) return fail(404, "project_not_visible", `That account cannot see a Jira project called ${project} on ${site}. Check the site and the project key.`);
  if (res.status !== 200) return fail(502, "jira_error", `Jira answered ${res.status} when checking the project.`);
  const types = (Array.isArray(rec(res.json)["issueTypes"]) ? (rec(res.json)["issueTypes"] as unknown[]) : []).map((t) => str(rec(t)["name"])).filter(Boolean);
  const chosen = types.find((t) => t.toLowerCase() === issueType.toLowerCase());
  if (types.length > 0 && !chosen) {
    return fail(409, "issue_type_missing", `${project} has no issue type called ${issueType}. It has: ${types.slice(0, 8).join(", ")}.`);
  }

  const place = { provider: "jira" as const, target: project, site };
  const sameProject = before !== null && placeOf(before) === placeOf(place);
  const row = { target: project, site, accountEmail: email, issueType: chosen ?? issueType, credentialEncrypted: encryptSecret(token) };
  await db.insert(ticketDestinationsTable).values({ userId, provider: "jira", ...row })
    .onConflictDoUpdate({
      target: [ticketDestinationsTable.userId, ticketDestinationsTable.provider],
      set: { ...row, createdAt: new Date(), ...(sameProject ? {} : { autoFile: false }) },
    });
  return { ok: true, target: project };
}

// ── Filing ────────────────────────────────────────────────────────────────────

export interface FiledTicket { ok: true; created: boolean; provider: Provider; ticketKey: string; ticketUrl: string }

export async function fileTicket(input: { userId: string; provider: Provider; reportId: string; findingId: string }): Promise<FiledTicket | Failure> {
  const { userId, provider } = input;
  const [dest] = await db.select().from(ticketDestinationsTable)
    .where(and(eq(ticketDestinationsTable.userId, userId), eq(ticketDestinationsTable.provider, provider)));
  if (!dest) return fail(409, "no_destination", `Connect ${NAME[provider]} first (Settings, Linear and Jira).`);

  const [report] = await db.select({ id: reportsTable.id, targetUrl: reportsTable.targetUrl, data: reportsTable.data }).from(reportsTable)
    .where(and(eq(reportsTable.id, input.reportId), eq(reportsTable.userId, userId)));
  const finding = report ? findingOf(report.data, input.findingId) : null;
  if (!report || !finding) return fail(404, "finding_not_found", "That finding was not found in your report.");

  const key = findingKey(report.targetUrl, finding.name);
  const place = placeOf(dest);
  const reportUrl = `${APP_ORIGIN}/report/${report.id}`;

  // Two requests for the same finding must not both reach the provider, or it would file two tickets. They take turns on a
  // lock keyed to the finding; the second then finds the first one's ticket. Released when the transaction ends.
  return db.transaction(async (tx): Promise<FiledTicket | Failure> => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`${userId}\n${provider}\n${place}\n${key}`}))`);

    const [existing] = await tx.select().from(ticketsTable).where(and(
      eq(ticketsTable.userId, userId), eq(ticketsTable.provider, provider), eq(ticketsTable.destination, place), eq(ticketsTable.findingKey, key)));
    if (existing) return { ok: true, created: false, provider, ticketKey: existing.ticketKey, ticketUrl: existing.ticketUrl };

    const since = new Date(Date.now() - 24 * 60 * 60_000);
    const [{ n } = { n: 0 }] = await tx.select({ n: sql<number>`count(*)::int` }).from(ticketsTable)
      .where(and(eq(ticketsTable.userId, userId), gte(ticketsTable.createdAt, since)));
    if (n >= DAILY_TICKETS) return fail(429, "daily_limit", `You have filed ${DAILY_TICKETS} tickets in the last day. Try again tomorrow.`);

    let secret: string;
    try { secret = decryptSecret(dest.credentialEncrypted); } catch {
      return fail(409, "token_unreadable", `The saved ${NAME[provider]} credential can no longer be read. Save it again in Settings.`);
    }

    const title = issueTitle(finding, report.targetUrl);
    const made = provider === "linear"
      ? await createLinear(dest.externalId ?? "", secret, title, linearDescription(finding, { targetUrl: report.targetUrl, reportUrl }), finding.severity)
      : await createJira(dest, secret, title, finding, { targetUrl: report.targetUrl, reportUrl });
    if (!made.ok) return made;

    await tx.insert(ticketsTable)
      .values({ userId, provider, destination: place, findingKey: key, reportId: report.id, ticketKey: made.ticketKey, ticketUrl: made.ticketUrl })
      .onConflictDoNothing();
    return { ok: true, created: true, provider, ticketKey: made.ticketKey, ticketUrl: made.ticketUrl };
  });
}

type Made = { ok: true; ticketKey: string; ticketUrl: string } | Failure;

async function createLinear(teamId: string, key: string, title: string, description: string, severity: string): Promise<Made> {
  const res = await linear(
    key,
    "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { identifier url } } }",
    { input: { teamId, title, description, priority: linearPriority(severity) } },
  );
  if (!res) return fail(502, "linear_unreachable", "Linear could not be reached. Nothing was filed; try again.");
  if (res.authFailed) return fail(401, "token_rejected", "Linear rejected the saved key. It may have been revoked: save a new one in Settings.");
  const created = rec(rec(res.data["issueCreate"])["issue"]);
  const ticketKey = str(created["identifier"]);
  const ticketUrl = str(created["url"]);
  if (res.errors.length > 0 && !ticketKey) {
    const forbidden = res.errors.some((e) => /forbidden|permission|not.?found|entity/i.test(str(e["message"])));
    if (forbidden) return fail(403, "no_permission", "The Linear key cannot create issues in that team. Check the key's access and the team.");
  }
  if (res.status !== 200 || !ticketKey || !ticketUrl) return fail(502, "linear_error", `Linear answered ${res.status} and did not create the issue.`);
  return { ok: true, ticketKey, ticketUrl };
}

async function createJira(dest: typeof ticketDestinationsTable.$inferSelect, token: string, title: string, finding: Parameters<typeof jiraDescription>[0], ctx: { targetUrl: string; reportUrl: string }): Promise<Made> {
  if (!dest.site || !dest.accountEmail) return fail(409, "token_unreadable", "The saved Jira connection is incomplete. Save it again in Settings.");
  const origin = jiraOrigin(dest.site);
  const priority = jiraPriority(finding.severity);
  const fields: Record<string, unknown> = {
    project: { key: dest.target },
    summary: title.slice(0, 250),
    issuetype: { name: dest.issueType ?? DEFAULT_ISSUE_TYPE },
    description: jiraDescription(finding, ctx),
    labels: ISSUE_LABELS,
    ...(priority ? { priority: { name: priority } } : {}),
  };
  const post = (f: Record<string, unknown>) => call(`${origin}/rest/api/3/issue`, jiraAuth(dest.accountEmail!, token), { method: "POST", body: { fields: f } });

  let res = await post(fields);
  // Priority and labels are optional extras that a project may not put on its create screen: if that is the only complaint,
  // file the ticket without them rather than not at all.
  if (res?.status === 400) {
    const complaints = Object.keys(rec(rec(res.json)["errors"]));
    const optional = ["priority", "labels"];
    if (complaints.length > 0 && complaints.every((c) => optional.includes(c))) {
      const { priority: _p, labels: _l, ...rest } = fields;
      void _p; void _l;
      res = await post(rest);
    }
  }
  if (!res) return fail(502, "jira_unreachable", "Jira could not be reached. Nothing was filed; try again.");
  if (res.status === 401) return fail(401, "token_rejected", "Jira rejected the saved token. It may have been revoked: save a new one in Settings.");
  if (res.status === 403 || res.status === 404) return fail(403, "no_permission", `The account cannot create tickets in ${dest.target}. Give it the Create issues permission on that project.`);
  const ticketKey = str(rec(res.json)["key"]);
  if (res.status !== 201 || !ticketKey) return fail(502, "jira_error", `Jira answered ${res.status} and did not create the ticket.`);
  return { ok: true, ticketKey, ticketUrl: `${origin}/browse/${ticketKey}` };
}

export interface TicketRef { ticketKey: string; ticketUrl: string }

/** The tickets already filed for the findings in this report, by finding id then provider, for the destinations currently connected. */
export async function ticketsForReport(userId: string, reportId: string): Promise<Record<string, Partial<Record<Provider, TicketRef>>>> {
  const dests = await getDestinations(userId);
  if (dests.length === 0) return {};
  const [report] = await db.select({ targetUrl: reportsTable.targetUrl, data: reportsTable.data }).from(reportsTable)
    .where(and(eq(reportsTable.id, reportId), eq(reportsTable.userId, userId)));
  if (!report) return {};
  const vulns = Array.isArray(rec(report.data)["vulnerabilities"]) ? (rec(report.data)["vulnerabilities"] as unknown[]).map(rec) : [];
  const keyOf = new Map<string, string>();
  for (const v of vulns) if (str(v["id"]) && str(v["category"]) !== "Scan Coverage") keyOf.set(str(v["id"]), findingKey(report.targetUrl, str(v["name"])));
  if (keyOf.size === 0) return {};

  const rows = await db.select().from(ticketsTable).where(and(eq(ticketsTable.userId, userId), inArray(ticketsTable.findingKey, [...new Set(keyOf.values())])));
  const out: Record<string, Partial<Record<Provider, TicketRef>>> = {};
  for (const [id, key] of keyOf) {
    for (const d of dests) {
      const r = rows.find((x) => x.provider === d.provider && x.destination === placeOf(d) && x.findingKey === key);
      if (r) (out[id] ??= {})[d.provider] = { ticketKey: r.ticketKey, ticketUrl: r.ticketUrl };
    }
  }
  return out;
}
