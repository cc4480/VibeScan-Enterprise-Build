/**
 * What a Linear or Jira ticket for a finding says. Pure: no network, no database.
 *
 * The same cleaning as a GitHub issue (see githubIssueBody.ts): everything that came from the scanned site is untrusted text
 * going into somebody's tracker, so secrets are redacted and length is bounded. Linear takes Markdown, so it gets the GitHub
 * issue text as is. Jira Cloud takes Atlassian Document Format, a JSON tree rather than markup: nothing in it is parsed as
 * HTML or as a mention, so text goes in as text and the evidence goes in a code block.
 */
import { SEVERITY_WORD, EVIDENCE_MAX, cut, issueBody, redactSecrets, type IssueFinding } from "./githubIssueBody";

const TEXT_MAX = 4_000;

/** Linear priority: 1 urgent, 2 high, 3 medium, 4 low, 0 none. */
export function linearPriority(severity: string): number {
  switch (severity.toLowerCase()) {
    case "critical": return 1;
    case "high": return 2;
    case "medium": return 3;
    case "low": return 4;
    default: return 0;
  }
}

/** Jira's standard priority names; a project that renamed them simply ignores the field (see tickets.ts). */
export function jiraPriority(severity: string): string | null {
  switch (severity.toLowerCase()) {
    case "critical": return "Highest";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    default: return null;
  }
}

export const linearDescription = issueBody;

// ── Atlassian Document Format ─────────────────────────────────────────────────

type Mark = { type: "strong" } | { type: "link"; attrs: { href: string } };
export type AdfNode = { type: string; attrs?: Record<string, unknown>; content?: AdfNode[]; text?: string; marks?: Mark[] };

/** Control characters out (a newline stays), redacted, bounded. */
const clean = (s: string | null | undefined, max = TEXT_MAX) => cut(redactSecrets(s ?? "").replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]+/g, " ").trim(), max);

const text = (t: string, marks?: Mark[]): AdfNode => ({ type: "text", text: t, ...(marks ? { marks } : {}) });
const paragraph = (...content: AdfNode[]): AdfNode => ({ type: "paragraph", content: content.filter((n) => n.text !== ""), });
const heading = (t: string): AdfNode => ({ type: "heading", attrs: { level: 3 }, content: [text(t)] });

/** Paragraphs from blank-line separated text; ADF has no empty text nodes, so empty input gives none. */
function paragraphs(t: string): AdfNode[] {
  return t.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean).map((p) => paragraph(text(p)));
}

export function jiraDescription(f: IssueFinding, ctx: { targetUrl: string; reportUrl: string }): AdfNode {
  const sev = SEVERITY_WORD[f.severity.toLowerCase()] ?? f.severity;
  const refs = [f.cweId ?? "", f.wstgId ? `OWASP ${f.wstgId}` : ""].filter(Boolean).join(" · ");
  const evidence = cut(redactSecrets(f.evidence ?? "").replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]+/g, " ").trim(), EVIDENCE_MAX);
  const content: AdfNode[] = [
    paragraph(text(sev, [{ type: "strong" }]), text(` · ${clean(f.category, 120) || "Security"}${refs ? ` · ${clean(refs, 120)}` : ""}`)),
    paragraph(text("Site: ", [{ type: "strong" }]), text(clean(ctx.targetUrl, 300))),
    heading("What was found"),
    ...(paragraphs(clean(f.description)).length ? paragraphs(clean(f.description)) : [paragraph(text("No description."))]),
    ...(evidence ? [heading("Evidence"), { type: "codeBlock", content: [text(evidence)] } as AdfNode] : []),
    ...(f.solution ? [heading("How to fix it"), ...paragraphs(clean(f.solution))] : []),
    { type: "rule" },
    paragraph(
      text("Filed by SecScan from "),
      text("this report", [{ type: "link", attrs: { href: ctx.reportUrl } }]),
      text(". Closing this ticket does not tell SecScan the problem is fixed: use “Fixed this? Check it” on the finding to confirm."),
    ),
  ];
  return { type: "doc", version: 1, content } as AdfNode;
}
