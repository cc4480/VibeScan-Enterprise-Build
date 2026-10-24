/**
 * What a GitHub issue for a finding says. Pure: no network, no database.
 *
 * Everything that came from the scanned site (names, descriptions, evidence) is untrusted text going into somebody's issue
 * tracker, so it is cleaned on the way in:
 *   - secrets are redacted (an exposed .env finding must not copy the secret into a tracker, where it would then be
 *     readable by everyone with access to the repository and sit in its history);
 *   - an @mention is defused (a page cannot make SecScan ping a stranger, or a whole team, from the user's token);
 *   - HTML is escaped, so a finding cannot inject markup;
 *   - evidence goes in a code fence that no backtick inside it can close.
 */
import { createHash } from "node:crypto";
import { redactForLlm } from "./llmRedact";

export interface IssueFinding {
  id: string;
  name: string;
  severity: string;
  category: string;
  description: string;
  evidence?: string | null;
  solution?: string | null;
  cweId?: string | null;
  wstgId?: string | null;
}

export const ISSUE_LABELS = ["security", "secscan"];
const TITLE_MAX = 200;
export const EVIDENCE_MAX = 3_000;
const TEXT_MAX = 4_000;

/** `owner/name` from "owner/name", "https://github.com/owner/name" or "…/name.git"; null for anything else. */
export function parseRepo(input: string): { owner: string; repo: string; fullName: string } | null {
  const raw = input.trim().replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/\.git$/i, "").replace(/\/+$/, "");
  const m = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/.exec(raw);
  if (!m || m[2] === "." || m[2] === "..") return null;
  return { owner: m[1]!, repo: m[2]!, fullName: `${m[1]}/${m[2]}` };
}

/**
 * The same problem on the same site, however many scans find it. Not the finding's id (new every scan) and not the report's.
 * The site is its hostname and port: an issue for shop.example.com is not an issue for staging.example.com.
 */
export function findingKey(targetUrl: string, findingName: string): string {
  let site = targetUrl.trim().toLowerCase();
  try { const u = new URL(targetUrl); site = u.host.toLowerCase(); } catch { /* the raw text still separates sites */ }
  return createHash("sha256").update(`${site}\n${findingName.trim().toLowerCase()}`).digest("hex").slice(0, 32);
}

export const SEVERITY_WORD: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/**
 * Secrets as they appear in an exposed file or a response: known key formats (redactForLlm), then any assignment whose
 * name says it is secret (`JWT_SECRET=…`, `"password": "…"`, `Authorization: Bearer …`) and credentials inside a
 * connection string (`postgres://user:pass@host`). The name is kept, so the reader can see what was exposed without
 * being handed the value.
 */
export function redactSecrets(text: string): string {
  return redactForLlm(text)
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s:@/]+:[^\s@/]+@/gi, "$1<redacted>@")
    .replace(/\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[^\s"',;]+/gi, "$1<redacted>")
    .replace(
      /(["']?)([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|private[_-]?key|credential|dsn|salt|signing[_-]?key)[A-Za-z0-9_.-]*)\1(\s*[:=]\s*)(["']?)[^\s"',;&]{4,}\4/gi,
      (_m, q1: string, name: string, sep: string, q2: string) => `${q1}${name}${q1}${sep}${q2}<redacted>${q2}`,
    );
}

export const oneLine = (s: string) => s.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").replace(/\s+/g, " ").trim();
export const cut = (s: string, max: number) => (s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s);

/** A mention is `@` followed by a name; a zero-width space after the `@` keeps the text and removes the notification. */
const defuseMentions = (s: string) => s.replace(/@(?=[A-Za-z0-9])/g, "@​");
const escapeHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
/** Prose from a scan: redacted, HTML escaped, mentions defused, length bounded. */
export const prose = (s: string | null | undefined, max = TEXT_MAX) => cut(defuseMentions(escapeHtml(redactSecrets(s ?? ""))).trim(), max);

export function issueTitle(f: IssueFinding, targetUrl: string): string {
  let host = targetUrl;
  try { host = new URL(targetUrl).host; } catch { /* keep the raw text */ }
  const sev = SEVERITY_WORD[f.severity.toLowerCase()] ?? f.severity;
  return cut(defuseMentions(oneLine(redactSecrets(`[SecScan] ${sev}: ${f.name} (${host})`))), TITLE_MAX);
}

/** A code fence longer than any run of backticks inside the text, so the text cannot end it early. */
function fenced(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((r) => r.length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  return `${fence}\n${text}\n${fence}`;
}

export function issueBody(f: IssueFinding, ctx: { targetUrl: string; reportUrl: string }): string {
  const sev = SEVERITY_WORD[f.severity.toLowerCase()] ?? f.severity;
  const refs = [f.cweId ? `${f.cweId}` : "", f.wstgId ? `OWASP ${f.wstgId}` : ""].filter(Boolean).join(" · ");
  const evidence = cut(redactSecrets(f.evidence ?? "").trim(), EVIDENCE_MAX);
  return [
    `**${sev}** · ${prose(f.category, 120) || "Security"}${refs ? ` · ${prose(refs, 120)}` : ""}`,
    `**Site:** ${prose(ctx.targetUrl, 300)}`,
    "",
    "### What was found",
    prose(f.description) || "_No description._",
    ...(evidence ? ["", "### Evidence", fenced(evidence)] : []),
    ...(f.solution ? ["", "### How to fix it", prose(f.solution)] : []),
    "",
    "---",
    `Filed by SecScan from [this report](${ctx.reportUrl}). Closing this issue does not tell SecScan the problem is fixed: use "Fixed this? Check it" on the finding to confirm.`,
  ].join("\n");
}
