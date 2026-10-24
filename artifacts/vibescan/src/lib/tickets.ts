/**
 * What the Linear and Jira controls say. The server decides everything that matters (whether a ticket already exists, what is
 * stored, what is redacted: api-server lib/tickets.ts); this only words the states and never claims more than the server
 * returned.
 */
import type { AutoSeverity } from "./github-issues";
import { AUTO_SEVERITY_CHOICES } from "./github-issues";

export type Provider = "linear" | "jira";
export const PROVIDER_NAME: Record<Provider, string> = { linear: "Linear", jira: "Jira" };

export interface TicketDestination {
  provider: Provider;
  /** The Linear team key or the Jira project key. */
  target: string;
  site: string | null;
  accountEmail: string | null;
  issueType: string | null;
  autoFile: boolean;
  autoMinSeverity: AutoSeverity;
}

export interface TicketDestinations {
  /** False when the server cannot store a credential (no encryption key), so there is nothing to offer. */
  available: boolean;
  destinations: TicketDestination[];
}

export interface TicketRef { ticketKey: string; ticketUrl: string }

/** Only ever a link to Linear's or Jira Cloud's own pages: a value the server returned is still checked before it becomes an href. */
export function safeTicketHref(url: string): string | null {
  try {
    const u = new URL(url);
    const host = u.hostname;
    const ours = host === "linear.app" || host.endsWith(".linear.app") || host.endsWith(".atlassian.net");
    return u.protocol === "https:" && ours ? u.href : null;
  } catch {
    return null;
  }
}

/** Where a destination files, in words: "ENG on Linear", "SEC on acme.atlassian.net". */
export function destinationLabel(d: TicketDestination): string {
  return d.provider === "jira" && d.site ? `${d.target} on ${d.site}` : `${d.target} on ${PROVIDER_NAME[d.provider]}`;
}

export type TicketView =
  | { kind: "filed"; provider: Provider; label: string; href: string }
  | { kind: "create"; provider: Provider; label: string; detail: string; busy: boolean };

/**
 * One entry per connected system, for one finding: the ticket when it already exists, otherwise an offer to create it.
 * Nothing at all for a system that is not connected (the GitHub control already invites people to Settings).
 */
export function ticketViews(input: {
  destinations: TicketDestination[] | undefined;
  filed: Partial<Record<Provider, TicketRef>> | undefined;
  starting: Provider | null;
}): TicketView[] {
  const out: TicketView[] = [];
  for (const d of input.destinations ?? []) {
    const ref = input.filed?.[d.provider];
    const href = ref ? safeTicketHref(ref.ticketUrl) : null;
    if (ref && href) {
      out.push({ kind: "filed", provider: d.provider, label: `${ref.ticketKey} on ${PROVIDER_NAME[d.provider]}`, href });
      continue;
    }
    const busy = input.starting === d.provider;
    out.push({
      kind: "create", provider: d.provider, busy,
      label: busy ? `Creating the ${PROVIDER_NAME[d.provider]} ticket…` : `Create ${PROVIDER_NAME[d.provider]} ${d.provider === "linear" ? "issue" : "ticket"}`,
      detail: `Files this finding in ${destinationLabel(d)}. Secrets in the evidence are removed first.`,
    });
  }
  return out;
}

/** What the switch promises, in the words of what the server does (api-server lib/ticketsAuto.ts). */
export function ticketAutoNote(d: TicketDestination): string {
  const level = AUTO_SEVERITY_CHOICES.find((c) => c.value === d.autoMinSeverity)?.label.toLowerCase() ?? d.autoMinSeverity;
  return `When a scheduled scan finds a new problem (${level}) that the last scan did not have, a ticket is filed in ${destinationLabel(d)}. One per problem, at most 10 a scan; secrets in the evidence are removed first.`;
}

export interface LinearForm { team: string; apiKey: string }
export interface JiraForm { site: string; email: string; token: string; project: string; issueType: string }

/** What the Settings forms check before they send anything; the server checks again. */
export function linearFormError(f: LinearForm): string | null {
  if (!/^[A-Za-z][A-Za-z0-9]{0,9}$/.test(f.team.trim())) return "Enter the team key as it appears in your issue numbers, for example ENG.";
  if (!/^[A-Za-z0-9_-]{20,255}$/.test(f.apiKey.trim())) return "Paste the whole API key. It starts with lin_api_.";
  return null;
}

export function jiraFormError(f: JiraForm): string | null {
  const site = f.site.trim().toLowerCase().replace(/^https:\/\//, "").replace(/[/?#].*$/, "");
  if (!/^[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?(?:\.atlassian\.net)?$/.test(site)) return "Enter your Jira Cloud site, for example acme.atlassian.net.";
  if (!/^[^\s@]{1,100}@[^\s@]{1,200}$/.test(f.email.trim())) return "Enter the email address of the Atlassian account the token belongs to.";
  if (!/^[\x21-\x7e]{10,300}$/.test(f.token.trim())) return "Paste the whole API token.";
  if (!/^[A-Za-z][A-Za-z0-9_]{1,9}$/.test(f.project.trim())) return "Enter the project key as it appears in your ticket numbers, for example SEC.";
  return null;
}
