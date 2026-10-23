import { describe, it, expect } from "vitest";
import { extractSupabaseConfig, extractServiceRoleKey, jwtClaims, jwtRole } from "./supabase-probes-config";

/**
 * Reading the project URL and public key out of a production bundle.
 *
 * A Vite or Next build keeps the URL and key as string constants with their names renamed to one or two
 * letters, so the extractor cannot rely on `SUPABASE_ANON_KEY=`; the layout below is what a real bundle
 * of a Lovable-style app contains (checked against a built Vite bundle of the lab target, where the
 * client file becomes `const sM="https://<ref>.supabase.co",aM="eyJ…",Tn=cO(sM,aM,{auth:{…}})`).
 */

const REF = "abcdefghijklmnopqrst";
const OTHER_REF = "zyxwvutsrqponmlkjihg";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
/** A token with a real header and payload and a filler signature; nothing here is a working credential. */
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${"s".repeat(43)}`;

const ANON = jwt({ iss: "supabase", ref: REF, role: "anon", iat: 1700000000, exp: 2000000000 });
const ANON_NO_REF = jwt({ role: "anon", iss: "supabase", iat: 1600000000, exp: 1960000000 });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role", iat: 1700000000, exp: 2000000000 });
const AUTHENTICATED = jwt({ iss: "supabase", ref: REF, role: "authenticated", iat: 1700000000, exp: 2000000000 });
const FOREIGN_ANON = jwt({ iss: "supabase", ref: OTHER_REF, role: "anon", iat: 1700000000, exp: 2000000000 });

/** Library code in front of the app's code, as in a real bundle. */
const VENDOR = 'function Ee(e){return e}class Xt{constructor(e){this.opts=e}}const Q=e=>typeof e=="boolean"?`${e}`:e;'.repeat(300);

describe("extractSupabaseConfig on a production bundle", () => {
  it("reads a URL and key that were renamed to short constants", () => {
    const bundle = `${VENDOR}const sM="https://${REF}.supabase.co",aM="${ANON}",Tn=cO(sM,aM,{auth:{persistSession:!0}});${VENDOR}`;
    expect(extractSupabaseConfig(bundle)).toEqual({ projectRef: REF, anonKey: ANON, baseUrl: `https://${REF}.supabase.co` });
  });

  it("reads a key written before the URL", () => {
    const bundle = `${VENDOR}const aM="${ANON_NO_REF}",sM="https://${REF}.supabase.co";${VENDOR}`;
    expect(extractSupabaseConfig(bundle)?.anonKey).toBe(ANON_NO_REF);
  });

  it("still reads the named forms, which are not renamed in a development build", () => {
    expect(extractSupabaseConfig(`createClient("https://${REF}.supabase.co", "${ANON}")`)?.anonKey).toBe(ANON);
    expect(extractSupabaseConfig(`const u="https://${REF}.supabase.co"; const SUPABASE_ANON_KEY="${ANON}"`)?.anonKey).toBe(ANON);
    expect(extractSupabaseConfig(`const u="https://${REF}.supabase.co"; const SUPABASE_PUBLISHABLE_KEY = "${ANON}"`)?.anonKey).toBe(ANON);
  });

  it("reads a publishable key", () => {
    const key = "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH";
    const bundle = `${VENDOR}const sM="https://${REF}.supabase.co",aM="${key}";${VENDOR}`;
    expect(extractSupabaseConfig(bundle)?.anonKey).toBe(key);
  });

  it("pairs a lone publishable key with the lone project even when they are far apart", () => {
    const key = "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH";
    const bundle = `const sM="https://${REF}.supabase.co";${VENDOR}${VENDOR}const aM="${key}";`;
    expect(extractSupabaseConfig(bundle)?.anonKey).toBe(key);
  });

  it("pairs a key with a distant URL by the project the key itself names", () => {
    const bundle = `const sM="https://${REF}.supabase.co";${VENDOR}${VENDOR}const aM="${ANON}";`;
    expect(extractSupabaseConfig(bundle)?.anonKey).toBe(ANON);
  });

  it("does not take a distant token that names no project: it could be any JWT", () => {
    const bundle = `const sM="https://${REF}.supabase.co";${VENDOR}${VENDOR}const aM="${ANON_NO_REF}";`;
    expect(extractSupabaseConfig(bundle)).toBeNull();
  });
});

describe("extractSupabaseConfig never returns a credential that is not the public key", () => {
  it("skips the service_role key even when it sits closer to the URL than the anon key", () => {
    const bundle = `const sM="https://${REF}.supabase.co",sr="${SERVICE}",aM="${ANON}";`;
    expect(extractSupabaseConfig(bundle)?.anonKey).toBe(ANON);
  });

  it("returns nothing when the only key near the URL is the service_role key", () => {
    expect(extractSupabaseConfig(`const sM="https://${REF}.supabase.co",sr="${SERVICE}";`)).toBeNull();
  });

  it("does not take a signed-in user's token for the public key", () => {
    expect(extractSupabaseConfig(`const sM="https://${REF}.supabase.co",t="${AUTHENTICATED}";`)).toBeNull();
  });

  it("does not take a key issued for a different project", () => {
    expect(extractSupabaseConfig(`const sM="https://${REF}.supabase.co",aM="${FOREIGN_ANON}";`)).toBeNull();
  });

  it("clean twin: prefers the key for this project over a foreign one beside it", () => {
    const bundle = `const x="${FOREIGN_ANON}",sM="https://${REF}.supabase.co",aM="${ANON}";`;
    expect(extractSupabaseConfig(bundle)?.anonKey).toBe(ANON);
  });
});

describe("extractSupabaseConfig ignores the hosts the Supabase libraries use in their documentation", () => {
  // Found by listing the .supabase.co hosts inside @supabase/*: xyzcompany, project-id, example and
  // myproject appear in the comments of every client package. A development build keeps comments, and
  // taking one of those hosts for the site's backend would send requests to a stranger's project.
  const docs = (host: string) => `/** const supabase = createClient("https://${host}.supabase.co", "${ANON_NO_REF}") */`;

  it("skips an example host and uses the real one", () => {
    const bundle = `${docs("xyzcompany")}${docs("project-id")}${docs("example")}${docs("myproject")}const sM="https://${REF}.supabase.co",aM="${ANON}";`;
    expect(extractSupabaseConfig(bundle)?.projectRef).toBe(REF);
  });

  it("finds nothing when the only hosts are examples", () => {
    expect(extractSupabaseConfig(docs("xyzcompany") + docs("your-project-id"))).toBeNull();
  });
});

describe("extractSupabaseConfig on a page with no Supabase", () => {
  it("returns null", () => {
    expect(extractSupabaseConfig(`<html><script>const a="${ANON}"</script></html>`)).toBeNull();
  });
});

describe("token helpers", () => {
  it("reads the claims and role without checking a signature", () => {
    expect(jwtClaims(SERVICE)).toMatchObject({ role: "service_role", ref: REF });
    expect(jwtRole(ANON)).toBe("anon");
  });
  it("returns null for text that is not a token", () => {
    expect(jwtClaims("not.a.token")).toBeNull();
    expect(jwtRole("eyJ" + "a".repeat(60))).toBeNull();
  });
  it("finds a service_role key by its role claim whatever the variable is called", () => {
    expect(extractServiceRoleKey(`const x="${ANON}",q="${SERVICE}";`)).toBe(SERVICE);
    expect(extractServiceRoleKey(`const x="${ANON}";`)).toBeNull();
  });
});
