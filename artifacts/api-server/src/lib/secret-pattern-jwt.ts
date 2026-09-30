/**
 * Data module: JSON Web Token secret patterns and the classifier that splits them.
 * Extracted from secret-pattern-data.ts to keep that file's line count down.
 */

import type { SecretPattern } from "./secret-pattern-data";
import { jwtPayload } from "./publicKeys";

/** Three dot-separated base64url segments, the shape of a JWT. */
const JWT_PATTERN = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/;

/**
 * Claims that make a token speak for someone. A JWT carrying any of these
 * authenticates a principal; one carrying none identifies an account.
 */
const PRINCIPAL_CLAIMS = [
  "sub", "user_id", "userId", "uid", "email", "username", "name",
  "role", "roles", "scope", "scp", "permissions", "groups", "admin",
  "actor", "act", "client_id", "azp",
];

/**
 * Classifies a JWT-shaped string:
 *   "credential"  — carries an identity or authorization claim
 *   "publishable" — parses, but claims only account-level identifiers
 *   "not-a-jwt"   — too short, or the payload is not base64url JSON
 */
function jwtClass(match: string): "credential" | "publishable" | "not-a-jwt" {
  if (match.length <= 60) return "not-a-jwt";
  const payload = jwtPayload(match);
  if (payload === null) return "not-a-jwt";
  // Supabase anon keys are published deliberately. A service_role token is NOT: it carries a role
  // claim like any credential and falls through to "credential" below, whether or not a variable
  // name lets the dedicated Supabase check see it.
  if (payload.role === "anon") return "not-a-jwt";
  // jwt.io's debugger sample ({"sub":"1234567890","name":"John Doe"}) is pasted into docs and tests
  // everywhere; it identifies nobody.
  if (payload.sub === "1234567890" && payload.name === "John Doe") return "not-a-jwt";
  const hasPrincipal = PRINCIPAL_CLAIMS.some(
    (c) => payload[c] !== undefined && payload[c] !== null && payload[c] !== "",
  );
  return hasPrincipal ? "credential" : "publishable";
}

export const JWT_PATTERNS: SecretPattern[] = [
  // ── JSON Web Tokens ───────────────────────────────────────────────────────
  //
  // Two entries share one regex and split on a single question: does the token
  // identify a PRINCIPAL, or only a TENANT?
  //
  // A JWT carrying sub / user_id / email / role / scope authenticates someone,
  // and finding one in client source is a real credential leak. A JWT carrying
  // nothing but an account id and an issued-at is an identifier that a vendor
  // SDK is meant to ship publicly — the same category as a Stripe publishable
  // key or a Supabase anon key, both already excluded here.
  //
  // Without the split, nytimes.com was reported HIGH for a "hardcoded JWT" that
  // was an Iterate survey widget's apiKey inside Google Tag Manager, payload
  // {"company_id":"…","iat":…}. Publishing that as a credential leak would have
  // been a false accusation about a named third party.
  {
    name: "Hardcoded JWT Token in Source",
    skipPlaceholderCheck: true,
    firstPartyOnly: true,
    pattern: JWT_PATTERN,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A JWT (JSON Web Token) carrying an identity or authorization claim was found hardcoded in JavaScript source code. If this is a long-lived or non-expiring token, anyone who views this code is authenticated as the associated user or service account.",
    solution: "Immediately invalidate this token (rotate the JWT signing secret, or if using a token allowlist, remove this token). Never hardcode JWTs in source code. Tokens should be dynamically obtained at runtime and stored in memory, not in code.",
    validate: (m) => jwtClass(m) === "credential",
  },
  {
    name: "JWT-Shaped Publishable Key in Client Code (verify it is not a credential)",
    skipPlaceholderCheck: true,
    pattern: JWT_PATTERN,
    severity: "info", cvssScore: 0, cweId: "CWE-798",
    description: "A JWT-shaped value was found in client-side code, but its payload carries no identity or authorization claim — no subject, user, email, role or scope, only account-level identifiers. Vendor SDKs ship exactly this kind of token publicly to identify which account a widget belongs to, so on its own it is not a credential leak. It is reported so you can confirm that is what it is.",
    solution: "Confirm this token is your vendor's publishable or client-side key rather than a server credential that was pasted into the bundle. If it grants any access beyond identifying the account, rotate it and move it server-side.",
    validate: (m) => jwtClass(m) === "publishable",
  },
];
