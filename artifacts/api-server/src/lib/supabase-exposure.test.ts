import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { runSupabaseProbes } from "./supabase-probes.js";
import { checkSupabaseRLS } from "./probes.js";
import { classifyExposure, rowsAreOwned } from "./baasExposure.js";
import { analyzeJwts } from "./jwtAnalysis.js";
import { startBaasStub, useRealBaas, type BaasStub, type Recorded, type Reply } from "./baasStub.testkit";
import type { ScanVulnerability } from "./scanner";

/**
 * A table that is public by design must not be rated critical.
 *
 * Found with a Lovable-style target app: its clean twin has an `announcements` table (id, title, body, date)
 * that is readable by everyone on purpose. With the Supabase config visible, both Supabase checks rated it
 * CRITICAL "Tables Readable Without Authentication", because a table whose name is not on the list of
 * catalogue words (products, posts, faq…) was treated like a sensitive one. The clean twin must come back
 * clean, and the tables that are the problem (profiles, orders, per-user notes) must stay critical.
 *
 * The probes talk to a real local server that answers like a Supabase project (lib/baasStub.testkit.ts).
 */

const REF = "abcdefghijklmnopqrst";
const BASE = `https://${REF}.supabase.co`; // what the page declares; the probes reach the project through the stub
const PREFIX = `/supabase/${REF}`;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${"s".repeat(43)}`;
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon", iat: 1700000000, exp: 2000000000 });

const page = (tables: string[]) =>
  `<script>const sM="${BASE}",aM="${ANON}",Tn=cO(sM,aM);${tables.map((t) => `Tn.from("${t}").select("*");`).join("")}</script>`;

let stub: BaasStub;
beforeAll(async () => { stub = await startBaasStub(); });
afterAll(async () => { await stub.stop(); useRealBaas(); });
beforeEach(() => stub.clear());

/** What the anon key can read, by table. Anything else answers like a table with RLS on. */
function server(rowsByTable: Record<string, unknown[]>, opts: { writes?: boolean } = {}) {
  stub.onAny(new RegExp(`^${PREFIX}/`), (r: Recorded): Reply => {
    const rel = r.path.slice(PREFIX.length);
    const table = /^\/rest\/v1\/([^/]+)$/.exec(rel)?.[1];
    if (r.method === "GET" && table && r.query.has("select")) return { json: rowsByTable[table] ?? [] };
    if (r.method === "GET" && rel === "/rest/v1/") {
      // The project's OpenAPI listing, which names every table.
      return { json: { definitions: Object.fromEntries(Object.keys(rowsByTable).map((t) => [t, {}])) } };
    }
    if (r.method === "POST" && rel.startsWith("/rest/v1/")) {
      return opts.writes ? { status: 201, json: [{ id: 9 }] } : { status: 401, json: { code: "42501", message: "new row violates row-level security policy" } };
    }
    return { status: 401, json: { message: "Invalid API key" } };
  });
}

const probe = async (tables: string[]) => {
  const findings: ScanVulnerability[] = [];
  await runSupabaseProbes(page(tables), "deep", findings);
  return findings;
};
const bySeverity = (f: ScanVulnerability[], sev: string) => f.filter((x) => x.severity === sev);

const ANNOUNCEMENTS = [{ id: 1, title: "We moved", body: "Our new address is on the About page.", created_at: "2026-10-01T00:00:00Z" }];

describe("classifyExposure", () => {
  it("a table named like published content is public", () => {
    expect(classifyExposure("announcements", ANNOUNCEMENTS)).toBe("public");
    expect(classifyExposure("changelog", [{ version: "1.2", notes: "Faster." }])).toBe("public");
  });

  it("a table with an unfamiliar name and nothing personal in it is unclassified, not sensitive", () => {
    expect(classifyExposure("bulletin", [{ id: 1, title: "x", body: "y" }])).toBe("unclassified");
    expect(classifyExposure("notes", [{ a: 1 }])).toBe("unclassified");
  });

  it("rows that say whose they are make an unfamiliar table sensitive", () => {
    for (const col of ["user_id", "owner_id", "customer_id", "account_id", "tenant_id", "org_id", "workspace_id", "device_id", "session_id", "created_by", "uid", "userId"]) {
      expect(classifyExposure("notes", [{ id: 1, body: "x", [col]: "u-1" }])).toBe("sensitive");
    }
  });

  it("an author is not an owner: a public post has one", () => {
    expect(rowsAreOwned([{ id: 1, title: "x", author_id: "u-1" }])).toBe(false);
    expect(classifyExposure("posts", [{ id: 1, title: "x", author_id: "u-1" }])).toBe("public");
  });

  it("a public name still wins over an owner column, as before (reviews carry a user_id)", () => {
    expect(classifyExposure("reviews", [{ id: 1, stars: 5, user_id: "u-1" }])).toBe("public");
  });

  it("a sensitive name or a personal column still wins over everything", () => {
    expect(classifyExposure("profiles", ANNOUNCEMENTS)).toBe("sensitive");
    expect(classifyExposure("announcements", [{ id: 1, title: "x", contact_email: "a@b.co" }])).toBe("sensitive");
  });

  it("looks only at the sampled rows' own columns", () => {
    expect(rowsAreOwned([])).toBe(false);
    expect(rowsAreOwned(["user_id"])).toBe(false);
    expect(rowsAreOwned([null, [{ user_id: 1 }]])).toBe(false);
  });
});

describe("runSupabaseProbes: public-by-design tables", () => {
  it("clean twin: a readable announcements table is information, never critical", async () => {
    server({ announcements: ANNOUNCEMENTS });
    const findings = await probe(["announcements", "tasks"]);
    expect(stub.requests.length).toBeGreaterThan(0); // the probe really reached the (local) project
    expect(bySeverity(findings, "critical")).toEqual([]);
    expect(bySeverity(findings, "high")).toEqual([]);
    expect(bySeverity(findings, "medium")).toEqual([]);
    const note = findings.find((f) => /Public Content Tables/.test(f.name));
    expect(note?.severity).toBe("info");
    expect(note?.evidence).toContain("announcements");
  });

  it("clean twin: a readable table with an unfamiliar name and nothing personal is information, worded as a question", async () => {
    server({ bulletin: [{ id: 1, title: "Roof repairs", body: "Scaffolding goes up Monday." }] });
    const findings = await probe(["bulletin"]);
    expect(bySeverity(findings, "critical")).toEqual([]);
    const note = findings.find((f) => /Not Classified/.test(f.name));
    expect(note?.severity).toBe("info");
    expect(note?.cvssScore).toBe(0);
    expect(note?.evidence).toContain("bulletin");
    expect(note?.evidence).toContain("id, title, body");
    expect(note?.description).toMatch(/Confirm/);
  });
});

describe("runSupabaseProbes: the tables that are the problem stay critical", () => {
  it("a profiles table", async () => {
    server({ profiles: [{ id: "u1", display_name: "Sam" }] });
    const open = (await probe(["profiles"])).find((f) => /Tables Readable Without Authentication \(CVE/.test(f.name));
    expect(open?.severity).toBe("critical");
    expect(open?.evidence).toContain("profiles");
  });

  it("a per-user table the name does not give away", async () => {
    server({ notes: [{ id: 1, body: "my diary", user_id: "u-1" }] });
    const open = (await probe(["notes"])).find((f) => /Tables Readable Without Authentication \(CVE/.test(f.name));
    expect(open?.severity).toBe("critical");
    expect(open?.evidence).toContain("notes");
  });

  it("lists only the sensitive table in the critical finding when a public one is open beside it", async () => {
    server({ orders: [{ id: 1, total: 4 }], announcements: ANNOUNCEMENTS, bulletin: [{ id: 1, title: "x" }] });
    const findings = await probe(["orders", "announcements", "bulletin"]);
    const open = findings.find((f) => f.severity === "critical" && /Readable Without Authentication/.test(f.name))!;
    expect(open.evidence).toContain("Tables returning rows unauthenticated: orders");
    expect(open.evidence).not.toMatch(/announcements|bulletin/);
    expect(findings.find((f) => /Public Content/.test(f.name))?.evidence).toContain("announcements");
    expect(findings.find((f) => /Not Classified/.test(f.name))?.evidence).toContain("bulletin");
  });

  it("anonymous writes to a public table are still critical", async () => {
    server({ announcements: ANNOUNCEMENTS }, { writes: true });
    const w = (await probe(["announcements"])).find((f) => /Accept Unauthenticated Writes/.test(f.name));
    expect(w?.severity).toBe("critical");
    expect(w?.evidence).toContain("announcements");
  });

  it("anonymous writes to an unclassified table are still critical", async () => {
    server({ bulletin: [{ id: 1, title: "x" }] }, { writes: true });
    const w = (await probe(["bulletin"])).find((f) => /Accept Unauthenticated Writes/.test(f.name));
    expect(w?.severity).toBe("critical");
  });
});

describe("checkSupabaseRLS agrees", () => {
  it("clean twin: announcements and an unfamiliar harmless table are information only", async () => {
    server({ announcements: ANNOUNCEMENTS, bulletin: [{ id: 1, title: "x" }], tasks: [] });
    const out = await checkSupabaseRLS(page([]));
    expect(out.map((f) => f.severity)).toEqual(["info", "info"]);
    expect(out.map((f) => f.name).sort()).toEqual([
      "Supabase Public Content Tables Readable Without Authentication",
      "Supabase Tables Readable Without Authentication (Not Classified)",
    ]);
  });

  it("a per-user table is critical", async () => {
    server({ notes: [{ id: 1, body: "x", user_id: "u-1" }], announcements: ANNOUNCEMENTS });
    const out = await checkSupabaseRLS(page([]));
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("critical");
    expect(out[0]!.description).toContain("notes");
    expect(out[0]!.description).not.toContain("announcements");
  });
});

describe("the anon key's lifetime is not a finding", () => {
  // Supabase issues the anon key for ten years. It is public on purpose, so a MEDIUM "lifetime is 3650 days"
  // on it is a false alarm; it was the only medium on the clean twin of the test app.
  const iat = 1700000000;
  const tenYears = iat + 3650 * 86400;
  const anonKey = jwt({ iss: "supabase", ref: REF, role: "anon", iat, exp: tenYears });
  const sessionToken = jwt({ iss: "supabase", sub: "u-1", role: "authenticated", iat, exp: tenYears });

  it("clean twin: the anon key produces nothing", async () => {
    expect(await analyzeJwts({}, `<script>const k="${anonKey}"</script>`)).toEqual([]);
  });

  it("a ten-year session token is still reported", async () => {
    const out = await analyzeJwts({}, `<script>const k="${sessionToken}"</script>`);
    expect(out.some((v) => /Lifetime Is 3650 Days/.test(v.name))).toBe(true);
  });

  it("a token that says role anon but also names a subject is a session, and still counts", async () => {
    const odd = jwt({ iss: "x", sub: "u-1", role: "anon", iat, exp: tenYears });
    const out = await analyzeJwts({}, `<script>const k="${odd}"</script>`);
    expect(out.some((v) => /Lifetime Is 3650 Days/.test(v.name))).toBe(true);
  });
});
