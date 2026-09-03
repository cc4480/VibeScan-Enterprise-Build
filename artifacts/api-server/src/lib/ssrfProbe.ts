/**
 * Server-Side Request Forgery (SSRF) detection — OWASP A10.
 *
 * The scanner currently cannot see SSRF at all: a server tricked into fetching
 * an attacker URL produces nothing in its own response, so a black-box scan
 * reading only that response is blind to it. This closes that gap using the
 * out-of-band collector: plant a URL back to our own server in a parameter,
 * and if the target fetches it, the callback proves the vulnerability.
 *
 * Confidence is high because the signal is unambiguous. The planted token is
 * random and appears nowhere else, so a callback carrying it can only have come
 * from a server that received the URL we injected — there is no benign
 * explanation and effectively no false positive.
 *
 * ── What is tested ───────────────────────────────────────────────────────────
 *
 * Two surfaces feed this: parameters whose *name* suggests they carry a URL
 * (url, uri, callback, webhook, dest, redirect, image, feed, proxy, …), across
 * discovered API endpoints and the query string of the page itself. A URL-shaped
 * parameter is exactly what an SSRF looks for, so the false-positive risk of
 * injecting into unrelated fields is avoided by targeting these by name.
 *
 * ── Safety ───────────────────────────────────────────────────────────────────
 *
 * Every injected value points only at our own collector — never at an internal
 * range, a metadata endpoint, or any third party. The probe asks "does this
 * server fetch a URL I gave it", not "can I reach something sensitive", so it
 * cannot be used to pull data out of a target's internal network. GET only for
 * query parameters; body injection stays on read-shaped endpoints, the same
 * rule the other API probes follow.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch, type ScanCredentials } from "./http";
import { isDestructiveUrl } from "./destructive";
import { registerOobToken, tokensWithInteractions, isOobConfigured } from "./oobServer";
import type { ApiEndpoint } from "./apiSurface";

const TIMEOUT_MS = 8_000;
const MAX_INJECTIONS = 30;
// How long to wait for callbacks after the last request. An SSRF fetch is
// usually near-immediate, but a queued or retried one can lag.
const CALLBACK_WAIT_MS = 6_000;

/** Parameter names that carry a URL, and so are where SSRF lives. */
const URL_PARAM_RE =
  /^(url|uri|link|href|src|source|dest|destination|target|redirect|redirect_?uri|return_?url|next|callback|webhook|web_?hook|hook|feed|rss|proxy|fetch|load|image|image_?url|img|avatar|photo|thumbnail|document|file_?url|remote|endpoint|api_?url|host|domain|site|page_?url|open|out|to|u|q)$/i;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

interface Injection {
  token: string;
  /** Human-readable description for the evidence. */
  where: string;
}

export interface SsrfProbeInput {
  scanId: string | null;
  targetUrl: string;
  endpoints: ApiEndpoint[];
  credentials?: ScanCredentials;
}

/**
 * Is this a parameter worth planting an SSRF payload in?
 *
 * By name only. Injecting a URL into a `quantity` field tests nothing, and
 * scattering callback URLs across every parameter would just be noise.
 */
export function isUrlParam(name: string): boolean {
  return URL_PARAM_RE.test(name);
}

export async function runSsrfProbes(input: SsrfProbeInput): Promise<ScanVulnerability[]> {
  // No collector, nothing to detect with. Skip silently rather than plant URLs
  // no target could reach.
  if (!isOobConfigured()) return [];

  const injections: Injection[] = [];

  const plant = async (where: string): Promise<string | null> => {
    if (injections.length >= MAX_INJECTIONS) return null;
    const { token, url } = await registerOobToken(input.scanId, where);
    injections.push({ token, where });
    return url;
  };

  // ── 1. URL parameters on the page's own query string ──────────────────────
  try {
    const target = new URL(input.targetUrl);
    for (const [name] of target.searchParams) {
      if (!isUrlParam(name)) continue;
      const url = await plant(`query parameter "${name}" on ${target.pathname}`);
      if (!url) break;
      const probe = new URL(input.targetUrl);
      probe.searchParams.set(name, url);
      if (!isDestructiveUrl(probe.toString())) {
        await scanFetch(probe.toString(), {
          ...(input.credentials ? { as: input.credentials } : {}),
          timeoutMs: TIMEOUT_MS,
        });
      }
    }
  } catch {
    /* unparseable target URL — the API endpoints below still run */
  }

  // ── 2. URL parameters declared by discovered API endpoints ────────────────
  for (const endpoint of input.endpoints) {
    if (injections.length >= MAX_INJECTIONS) break;
    const concrete = endpoint.url.replace(/\{[^}]+\}/g, "1");
    if (isDestructiveUrl(concrete)) continue;

    for (const param of endpoint.params) {
      if (!isUrlParam(param.name)) continue;
      if (param.location === "header") continue;
      // A body field means sending a body, so only where that is a read.
      const isRead = endpoint.method === "GET" || endpoint.method === "HEAD";
      if (param.location === "body" && !isRead && !/\b(search|query|filter|preview|fetch|proxy)\b/i.test(concrete)) {
        continue;
      }

      const where = `${endpoint.method} ${new URL(concrete).pathname} — parameter "${param.name}"`;
      const url = await plant(where);
      if (!url) break;

      if (param.location === "query") {
        const probe = new URL(concrete);
        probe.searchParams.set(param.name, url);
        await scanFetch(probe.toString(), {
          ...(input.credentials ? { as: input.credentials } : {}),
          timeoutMs: TIMEOUT_MS,
        });
      } else if (param.location === "path") {
        const probe = concrete.replace(/\/1(?=\/|$)/, `/${encodeURIComponent(url)}`);
        await scanFetch(probe, {
          ...(input.credentials ? { as: input.credentials } : {}),
          timeoutMs: TIMEOUT_MS,
        });
      } else {
        await scanFetch(concrete, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ [param.name]: url }),
          ...(input.credentials ? { as: input.credentials } : {}),
          timeoutMs: TIMEOUT_MS,
        });
      }
    }
  }

  if (injections.length === 0) return [];

  // Give the target's server time to make the out-of-band request.
  await new Promise((r) => setTimeout(r, CALLBACK_WAIT_MS));

  const hit = await tokensWithInteractions(injections.map((i) => i.token));
  const confirmed = injections.filter((i) => hit.has(i.token));
  if (confirmed.length === 0) return [];

  return [
    vuln({
      name: "Server-Side Request Forgery (SSRF)",
      severity: "critical",
      category: "Server-Side Request Forgery",
      description:
        `The server fetched a URL supplied in ${confirmed.length} ` +
        `parameter${confirmed.length > 1 ? "s" : ""}: a request planted with a unique token reached our ` +
        `collector, which only happens if the target's own server made the call. An attacker can point the ` +
        `same parameter at your cloud metadata service to steal credentials, at internal admin panels not ` +
        `exposed to the internet, or at other services behind your firewall — the server makes the request ` +
        `with all the trust of being inside your network.`,
      evidence:
        `Each parameter was given a URL back to this scanner carrying a random token; a callback arrived ` +
        `for each listed:\n\n` +
        confirmed.map((i) => `  ${i.where}`).join("\n"),
      solution:
        "Do not fetch user-supplied URLs directly. Validate against an allowlist of permitted hosts, resolve " +
        "the hostname and reject any address in a private, loopback or link-local range (including the cloud " +
        "metadata address 169.254.169.254), and re-check after every redirect — a permitted host can 302 to " +
        "an internal one. Disabling redirects on the fetch and requiring https also closes common variants.",
      cweId: "CWE-918",
      cvssScore: 9.1,
      wstgId: "WSTG-INPV-19",
      confidence: 95,
    }),
  ];
}
