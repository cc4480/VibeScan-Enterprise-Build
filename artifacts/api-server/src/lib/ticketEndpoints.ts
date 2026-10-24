/**
 * Where Linear and Jira are. Linear has one API host; a Jira Cloud site has its own (acme.atlassian.net).
 *
 * Each can be pointed elsewhere by a test that needs the real code to talk to a server it controls. Read on every call, not
 * once at load, so a process (or a test) can change them without re-importing anything.
 */
const trim = (v: string) => v.trim().replace(/\/+$/, "");
const fromEnv = (name: string, fallback: string) => trim(process.env[name] ?? "") || fallback;

export const linearApi = (): string => fromEnv("LINEAR_API_URL", "https://api.linear.app");

/** A Jira Cloud site name: `acme.atlassian.net`. Anything else (another host, a port, a path) is refused, so a ticket call never goes to an address the user typed. */
const JIRA_SITE = /^[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?\.atlassian\.net$/;

/** `acme.atlassian.net` from "acme.atlassian.net", "https://acme.atlassian.net/jira/..." or "acme"; null for anything else. */
export function parseJiraSite(input: string): string | null {
  const raw = input.trim().toLowerCase().replace(/^https:\/\//, "").replace(/[/?#].*$/, "");
  if (/^[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$/.test(raw)) return `${raw}.atlassian.net`;
  return JIRA_SITE.test(raw) ? raw : null;
}

export const jiraOrigin = (site: string): string => fromEnv("JIRA_BASE_URL", `https://${site}`);
