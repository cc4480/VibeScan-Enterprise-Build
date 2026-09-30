/** Finding the project URL, anon key and any service-role key in client code. */
// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE DETECTION
// ─────────────────────────────────────────────────────────────────────────────

export interface SupabaseConfig {
  projectRef: string;
  anonKey: string;
  baseUrl: string;
}

/** Decode the role claim from a JWT without verifying the signature. */
export function jwtRole(token: string): string | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as
      Record<string, unknown>;
    return typeof payload["role"] === "string" ? payload["role"] : null;
  } catch {
    return null;
  }
}

export function isServiceRoleToken(token: string): boolean {
  return jwtRole(token) === "service_role";
}

/**
 * Extract the Supabase project URL and anon key from page content.
 * The anon key is designed to be public — this is NOT a vulnerability finding.
 * We need it to test the actual API endpoints.
 */
export function extractSupabaseConfig(content: string): SupabaseConfig | null {
  // Find the supabase project hostname
  const urlMatch = /https?:\/\/([\w-]+)\.supabase\.co/.exec(content);
  if (!urlMatch) return null;

  const projectRef = urlMatch[1]!;
  const baseUrl = `https://${projectRef}.supabase.co`;

  // Find anon/public key — skip any service_role token
  const keyPatterns = [
    // createClient("url", "key")
    /createClient\s*\(\s*["'][^"']*["']\s*,\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/,
    // explicit variable names
    /(?:SUPABASE_ANON_KEY|SUPABASE_KEY|supabaseAnonKey|supabaseKey|anonKey|anon_key)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
    // VITE / NEXT env var patterns
    /(?:VITE_SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|REACT_APP_SUPABASE_ANON_KEY)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
  ];

  for (const pattern of keyPatterns) {
    const m = pattern.exec(content);
    if (m?.[1] && !isServiceRoleToken(m[1])) {
      return { projectRef, anonKey: m[1], baseUrl };
    }
  }

  // Fallback: find any eyJ JWT near the supabase URL that isn't service_role
  const urlIdx = content.indexOf(baseUrl);
  if (urlIdx !== -1) {
    const window = content.slice(urlIdx, urlIdx + 1200);
    const jwtRx = /eyJ[A-Za-z0-9._-]{40,}/g;
    let m: RegExpExecArray | null;
    while ((m = jwtRx.exec(window)) !== null) {
      if (!isServiceRoleToken(m[0])) {
        return { projectRef, anonKey: m[0], baseUrl };
      }
    }
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

  // Scan all JWTs and check role claim
  const jwtRx = /eyJ[A-Za-z0-9._-]{20,}\.eyJ[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]*/g;
  let m: RegExpExecArray | null;
  while ((m = jwtRx.exec(content)) !== null) {
    if (isServiceRoleToken(m[0])) return m[0];
  }

  return null;
}
