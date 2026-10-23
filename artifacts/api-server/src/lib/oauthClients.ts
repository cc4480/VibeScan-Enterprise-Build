/**
 * Apps that connect through OAuth: registering them (RFC 7591) and deciding which
 * redirect addresses are safe.
 *
 * The redirect URI is where the authorization code is sent, so it is the thing an
 * attacker most wants to control. Rules, in order of importance:
 *   - An authorization request must use a redirect URI that EXACTLY matches one the
 *     app registered. No prefixes, no patterns.
 *   - https addresses, loopback addresses (an editor's own local callback on any
 *     port) and app-specific schemes (cursor://, vscode://) are allowed.
 *   - Schemes that can run code or read files are refused, and so is a fragment.
 *
 * Registration is open by design (an editor cannot ask for a key first); it is
 * rate limited in routes/oauth.ts and grants nothing by itself: a person still has
 * to sign in and approve each connection.
 */
import { randomBytes } from "node:crypto";
import { db, oauthClientsTable } from "@workspace/db";
import { eq } from "drizzle-orm";

const MAX_REDIRECT_URIS = 5;
const MAX_URI_LENGTH = 2048;
const MAX_NAME_LENGTH = 80;
const FORBIDDEN_SCHEMES = new Set(["javascript", "data", "file", "vbscript", "about", "blob", "ftp", "ws", "wss"]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export type UriCheck = { ok: true; uri: string } | { ok: false; reason: string };

export function checkRedirectUri(raw: unknown): UriCheck {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URI_LENGTH) return { ok: false, reason: "invalid length" };
  if (/[\s\u0000-\u001f]/.test(raw)) return { ok: false, reason: "contains whitespace or control characters" };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "not a URL" };
  }
  if (url.hash) return { ok: false, reason: "must not contain a fragment" };
  const scheme = url.protocol.slice(0, -1).toLowerCase();
  if (FORBIDDEN_SCHEMES.has(scheme)) return { ok: false, reason: `scheme ${scheme}: is not allowed` };

  if (scheme === "http") {
    // Plain http only to the machine itself; anywhere else the code would cross the network in the clear.
    if (!LOOPBACK_HOSTS.has(url.hostname.toLowerCase())) return { ok: false, reason: "http is only allowed for localhost" };
  } else if (scheme === "https") {
    if (url.username || url.password) return { ok: false, reason: "must not contain credentials" };
  }
  return { ok: true, uri: raw };
}

export function normaliseClientName(raw: unknown): string {
  const cleaned = String(raw ?? "").replace(/[\u0000-\u001f\u007f<>]/g, "").replace(/\s+/g, " ").trim();
  return (cleaned || "An app").slice(0, MAX_NAME_LENGTH);
}

export interface RegistrationInput {
  client_name?: unknown;
  redirect_uris?: unknown;
  token_endpoint_auth_method?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
}

export type Registration = { ok: true; name: string; redirectUris: string[] } | { ok: false; error: string; description: string };

/** Validate a dynamic registration request. Public clients only: no secrets are issued. */
export function validateRegistration(input: RegistrationInput): Registration {
  const bad = (description: string): Registration => ({ ok: false, error: "invalid_client_metadata", description });
  const uris = input.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0) return { ok: false, error: "invalid_redirect_uri", description: "redirect_uris is required" };
  if (uris.length > MAX_REDIRECT_URIS) return { ok: false, error: "invalid_redirect_uri", description: `at most ${MAX_REDIRECT_URIS} redirect URIs` };
  const accepted: string[] = [];
  for (const raw of uris) {
    const check = checkRedirectUri(raw);
    if (!check.ok) return { ok: false, error: "invalid_redirect_uri", description: `${String(raw).slice(0, 80)}: ${check.reason}` };
    if (!accepted.includes(check.uri)) accepted.push(check.uri);
  }
  const method = input.token_endpoint_auth_method;
  if (method !== undefined && method !== "none") return bad("only token_endpoint_auth_method \"none\" (a public client using PKCE) is supported");
  const grants = input.grant_types;
  if (grants !== undefined && (!Array.isArray(grants) || grants.some((g) => g !== "authorization_code" && g !== "refresh_token"))) {
    return bad("grant_types may only be authorization_code and refresh_token");
  }
  const responses = input.response_types;
  if (responses !== undefined && (!Array.isArray(responses) || responses.some((r) => r !== "code"))) return bad("response_types may only be code");
  return { ok: true, name: normaliseClientName(input.client_name), redirectUris: accepted };
}

export async function registerClient(name: string, redirectUris: string[]) {
  const clientId = `mcp_${randomBytes(18).toString("base64url")}`;
  await db.insert(oauthClientsTable).values({ clientId, name, redirectUris });
  return { clientId, name, redirectUris };
}

export async function findClient(clientId: unknown) {
  if (typeof clientId !== "string" || !/^mcp_[A-Za-z0-9_-]{20,40}$/.test(clientId)) return null;
  const [row] = await db.select().from(oauthClientsTable).where(eq(oauthClientsTable.clientId, clientId)).limit(1);
  return row ?? null;
}

/** Exact match against what the app registered. Never a prefix, never a pattern. */
export function redirectUriAllowed(client: { redirectUris: string[] }, uri: unknown): uri is string {
  return typeof uri === "string" && client.redirectUris.includes(uri);
}

/** What the person is told about where they are going back to: the host, not the whole URL. */
export function describeRedirect(uri: string): { host: string; kind: "web" | "local" | "app" } {
  try {
    const url = new URL(uri);
    const scheme = url.protocol.slice(0, -1);
    if (scheme === "https") return { host: url.host, kind: "web" };
    if (scheme === "http") return { host: url.host, kind: "local" };
    return { host: `${scheme}://${url.host}`.replace(/\/$/, ""), kind: "app" };
  } catch {
    return { host: "unknown", kind: "app" };
  }
}
