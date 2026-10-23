/** Finding the project URL, anon key and any service-role key in client code. */
import { supabaseProjectOrigin } from "./baasEndpoints";
// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE DETECTION
// ─────────────────────────────────────────────────────────────────────────────

export interface SupabaseConfig {
  projectRef: string;
  anonKey: string;
  baseUrl: string;
}

/** The claims of a JWT, read without verifying the signature; null when the text is not one. */
export function jwtClaims(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload: unknown = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return payload !== null && typeof payload === "object" && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Decode the role claim from a JWT without verifying the signature. */
export function jwtRole(token: string): string | null {
  const role = jwtClaims(token)?.["role"];
  return typeof role === "string" ? role : null;
}

export function isServiceRoleToken(token: string): boolean {
  return jwtRole(token) === "service_role";
}

// A key as the client libraries use it: the legacy JWT (anon) or the newer publishable key.
const KEY_BODY = String.raw`(eyJ[A-Za-z0-9._-]{40,}|sb_publishable_[A-Za-z0-9_-]{20,})`;

/** Keys the code names as the project's public key. A minifier removes the names, hence the passes below. */
const NAMED_KEY_PATTERNS: RegExp[] = [
  // createClient("url", "key")
  new RegExp(String.raw`createClient\s*\(\s*["'][^"']*["']\s*,\s*["']` + KEY_BODY + `["']`, "g"),
  // explicit variable names
  new RegExp(
    String.raw`(?:SUPABASE_ANON_KEY|SUPABASE_PUBLISHABLE_KEY|SUPABASE_KEY|supabaseAnonKey|supabasePublishableKey|supabaseKey|publishableKey|anonKey|anon_key|apikey)\s*[:=]\s*["']` + KEY_BODY + `["']`,
    "gi",
  ),
  // VITE / NEXT env var patterns
  new RegExp(
    String.raw`(?:VITE|NEXT_PUBLIC|REACT_APP)_SUPABASE_(?:ANON|PUBLISHABLE)_KEY\s*[:=]\s*["']` + KEY_BODY + `["']`,
    "gi",
  ),
];

/**
 * Project names the Supabase libraries and their documentation use in examples. A production bundle
 * has its comments stripped, but an unminified or development build keeps them, and a host named in
 * an example is never this site's backend: it must not be probed.
 */
const EXAMPLE_REF = /^(?:xyzcompany|project[-_]?(?:id|ref)|my[-_]?project|your[-_]?(?:supabase[-_]?)?project(?:[-_]?(?:id|ref))?|example|ref|x{3,})$/i;

/** How far from the project URL a key can sit and still be read as that project's key. */
const KEY_DISTANCE = 1200;
/** A bundle has a handful of tokens; this only bounds the work on a pathological one. */
const MAX_TOKENS = 60;
const MAX_URL_SITES = 24;

// The lookbehind keeps a start from sitting inside a longer run of token characters: a script of repeated
// `eyJ` would otherwise cost the square of its length (see secret-pattern-jwt.ts).
const JWT_SHAPE = /eyJ(?<![A-Za-z0-9_-]eyJ)[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const PUBLISHABLE_SHAPE = /\bsb_publishable_[A-Za-z0-9_-]{20,}/g;

interface Token { value: string; index: number }

function tokensIn(content: string, shape: RegExp): Token[] {
  const out: Token[] = [];
  for (const m of content.matchAll(shape)) {
    out.push({ value: m[0], index: m.index ?? 0 });
    if (out.length >= MAX_TOKENS) break;
  }
  return out;
}

/**
 * How well a token fits as the public key of project `ref`: 2 = the anon/publishable key, 1 = a token
 * that says nothing about its role (kept, as before), 0 = not usable: the service_role key or any other
 * role (those are never sent as the public key), or a key that names a different project.
 */
function keyFit(token: string, ref: string): 0 | 1 | 2 {
  if (token.startsWith("sb_publishable_")) return 2;
  const claims = jwtClaims(token);
  if (!claims) return 1;
  const claimedRef = claims["ref"];
  if (typeof claimedRef === "string" && claimedRef.toLowerCase() !== ref.toLowerCase()) return 0;
  const role = claims["role"];
  if (role === "anon") return 2;
  return typeof role === "string" ? 0 : 1;
}

/** Every project URL in the content, grouped by project, in order of first appearance. */
function projectSites(content: string): Array<{ ref: string; indexes: number[] }> {
  const byRef = new Map<string, { ref: string; indexes: number[] }>();
  for (const m of content.matchAll(/https?:\/\/([\w-]+)\.supabase\.co/g)) {
    const ref = m[1]!;
    if (EXAMPLE_REF.test(ref)) continue;
    const site = byRef.get(ref.toLowerCase()) ?? { ref, indexes: [] };
    if (site.indexes.length < MAX_URL_SITES) site.indexes.push(m.index ?? 0);
    byRef.set(ref.toLowerCase(), site);
  }
  return [...byRef.values()];
}

/**
 * Extract the Supabase project URL and anon key from page or bundle content.
 * The anon key is designed to be public — this is NOT a vulnerability finding.
 * We need it to test the actual API endpoints.
 *
 * The content may be the page, a first-party script, or both. In a production build the URL and key
 * are string constants in the bundle, their names renamed to one or two letters
 * (`const a="https://<ref>.supabase.co",b="eyJ…"`), so the key is looked for by name, then next to
 * the URL, then by the project reference the key itself carries. The service_role key is never
 * returned, and neither is a key issued for a different project.
 */
export function extractSupabaseConfig(content: string): SupabaseConfig | null {
  const sites = projectSites(content);
  if (sites.length === 0) return null;

  const jwts = tokensIn(content, JWT_SHAPE);
  const publishable = tokensIn(content, PUBLISHABLE_SHAPE);
  const nearby = [...jwts, ...publishable];

  for (const { ref, indexes } of sites) {
    const found = (anonKey: string): SupabaseConfig => ({ projectRef: ref, anonKey, baseUrl: supabaseProjectOrigin(ref) });

    // 1. A key the code names as the public key.
    for (const pattern of NAMED_KEY_PATTERNS) {
      for (const m of content.matchAll(pattern)) {
        if (m[1] && keyFit(m[1], ref) > 0) return found(m[1]);
      }
    }

    // 2. The best-fitting key written next to one of the URLs (the anon key over an unlabelled token,
    //    then the nearer one).
    let best: { token: string; fit: number; distance: number } | null = null;
    for (const at of indexes) {
      for (const t of nearby) {
        const distance = Math.abs(t.index - at);
        if (distance > KEY_DISTANCE) continue;
        const fit = keyFit(t.value, ref);
        if (fit === 0) continue;
        if (!best || fit > best.fit || (fit === best.fit && distance < best.distance)) best = { token: t.value, fit, distance };
      }
    }
    if (best) return found(best.token);

    // 3. A key that says in its own claims it belongs to this project, wherever it sits.
    const own = jwts.find((t) => {
      const claims = jwtClaims(t.value);
      return typeof claims?.["ref"] === "string" && claims["ref"].toLowerCase() === ref.toLowerCase() && keyFit(t.value, ref) === 2;
    });
    if (own) return found(own.value);

    // 4. A single publishable key and a single project in the content can only belong to each other.
    const distinct = [...new Set(publishable.map((t) => t.value))];
    if (sites.length === 1 && distinct.length === 1) return found(distinct[0]!);
  }

  return null;
}

/**
 * Detect the Supabase service_role key — this DOES bypass all RLS and must
 * never appear in frontend JavaScript.
 */
export function extractServiceRoleKey(content: string): string | null {
  // Explicit variable names
  const explicitPatterns = [
    /(?:serviceRoleKey|service_role_key|SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE_KEY|serviceRole)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
  ];
  for (const p of explicitPatterns) {
    const m = p.exec(content);
    if (m?.[1] && isServiceRoleToken(m[1])) return m[1];
  }

  // Scan all JWTs and check role claim. A token's segments are base64url, so a dot ends one; the
  // lookbehind keeps a start from sitting inside a longer run (time grew with the square of the length).
  const jwtRx = /eyJ(?<![A-Za-z0-9_-]eyJ)[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]*/g;
  let m: RegExpExecArray | null;
  while ((m = jwtRx.exec(content)) !== null) {
    if (isServiceRoleToken(m[0])) return m[0];
  }

  return null;
}
