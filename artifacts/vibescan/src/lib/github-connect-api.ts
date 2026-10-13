/**
 * Connect GitHub, from the scan form. Connecting is a full-page trip to GitHub and back through the server
 * (GET /api/github/connect, which returns to /scan?github=<outcome>); this file only words the outcome and reads or
 * forgets the connections.
 */
import { customFetch } from "@workspace/api-client-react";

export interface GithubConnection { installationId: number; accountLogin: string | null }
export interface ConnectedRepository { fullName: string; private: boolean; url: string; installationId: number }
export interface GithubRepos { available: boolean; connections: GithubConnection[]; repositories: ConnectedRepository[] }

/** The server route that starts the trip to GitHub. A plain link, not a fetch: it is a page navigation. */
export const CONNECT_HREF = "/api/github/connect";

export const getGithubRepos = () => customFetch<GithubRepos>("/api/github/repos");

export const disconnectGithub = (installationId: number) =>
  customFetch<{ removed: boolean }>(`/api/github/installations/${installationId}`, { method: "DELETE" });

export type ConnectOutcome = "connected" | "none" | "expired" | "unavailable" | "error";

/** What to tell the person after GitHub sends them back, or null for a URL that carries no outcome. */
export function connectOutcomeMessage(search: string): { tone: "good" | "warn"; text: string } | null {
  const outcome = new URLSearchParams(search).get("github");
  switch (outcome as ConnectOutcome | null) {
    case "connected":
      return { tone: "good", text: "GitHub is connected. Pick a repository below to read it with this scan." };
    case "none":
      return { tone: "warn", text: "GitHub did not list any repositories shared with SecScan. Connect again and choose at least one repository." };
    case "expired":
      return { tone: "warn", text: "That GitHub connection could not be confirmed, so nothing was saved. Start it again from this page." };
    case "unavailable":
      return { tone: "warn", text: "Connecting GitHub is not available right now. You can still check any public repository by its address." };
    case "error":
      return { tone: "warn", text: "GitHub did not finish connecting, so nothing was saved. Please try again." };
    default:
      return null;
  }
}

/** The value the repository field takes for a repository picked from the list. */
export const repoFieldValue = (r: ConnectedRepository) => `https://github.com/${r.fullName}`;
