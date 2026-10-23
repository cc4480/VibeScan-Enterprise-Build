import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { runSupabaseProbes } from "./supabase-probes.js";
import { checkSupabaseRLS } from "./probes.js";
import { extractTableNamesFromContent, extractStorageBucketNames } from "./supabase-probes-tables.js";
import { probeSupabaseStorageContents } from "./baasDepth.js";
import { startBaasStub, useRealBaas, type BaasStub, type Reply } from "./baasStub.testkit";
import type { ScanVulnerability } from "./scanner";

/**
 * The Supabase checks given a production bundle instead of a page.
 *
 * The bundle below has the layout of a built Vite app: library code first, then the app's own code with
 * the project URL and key as renamed constants, `.from("table")` calls on a renamed client, and a
 * `.storage.from("bucket")` call. The probes talk to a real local server that answers like a Supabase project
 * (lib/baasStub.testkit.ts).
 */

const REF = "abcdefghijklmnopqrst";
const BASE = `https://${REF}.supabase.co`; // what the code declares
const PREFIX = `/supabase/${REF}`;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${"s".repeat(43)}`;
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon", iat: 1700000000, exp: 2000000000 });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role", iat: 1700000000, exp: 2000000000 });

const VENDOR = 'function Ee(e){return e}class Xt{constructor(e){this.opts=e}}const Q=e=>typeof e=="boolean"?`${e}`:e;'.repeat(400);

/** Library code that also calls `.from("…")` with a literal, as bundled libraries do. */
const VENDOR_FROM = 'const t=Array.from("abc"),u=Buffer.from("hex"),w=Uint8Array.from("zz");';

const bundle = (opts: { service?: boolean } = {}) =>
  `${VENDOR}${VENDOR_FROM}const sM="${BASE}",aM="${ANON}",Tn=cO(sM,aM,{auth:{persistSession:!0}});` +
  (opts.service ? `const adm=cO(sM,"${SERVICE}");` : "") +
  `async function load(){const {data:a}=await Tn.from("tasks").select("*");const {data:b}=await Tn.from("orders").select("*");` +
  `const {data:c}=await Tn.storage.from("avatars").list();return[a,b,c]}${VENDOR}`;

const json = (data: unknown, status = 200): Reply => ({ json: data, status });

let stub: BaasStub;
beforeAll(async () => { stub = await startBaasStub(); });
afterAll(async () => { await stub.stop(); useRealBaas(); });
beforeEach(() => stub.clear());

/** Whatever is asked, the service_role key must never be the one sent. */
const serviceKeyNeverSent = () => stub.requests.every((r) => !JSON.stringify(r.headers).includes(SERVICE));

describe("table and bucket names read from a bundle", () => {
  it("takes table names from .from() calls and leaves out storage buckets and built-ins", () => {
    expect(extractTableNamesFromContent(bundle()).sort()).toEqual(["orders", "tasks"]);
  });

  it("reads the same call written across lines in an unminified build", () => {
    const src = `supabase\n  .storage\n  .from("avatars")\n  .upload(p, f); supabase\n  .from("profiles")\n  .select()`;
    expect(extractTableNamesFromContent(src)).toEqual(["profiles"]);
    expect(extractStorageBucketNames(src)).toEqual(["avatars"]);
  });

  it("names the storage buckets the code opens", () => {
    expect(extractStorageBucketNames(bundle())).toEqual(["avatars"]);
    expect(extractStorageBucketNames(`x.storage.from(bucketName)`)).toEqual([]);
  });
});

describe("runSupabaseProbes given a bundle", () => {
  /** Anon reads of `tasks` come back empty (RLS on); `orders` returns rows (RLS off); storage lists nothing. */
  function serve() {
    stub.onAny(new RegExp(`^${PREFIX}/`), (r): Reply => {
      const rel = r.path.slice(PREFIX.length);
      if (rel === "/rest/v1/orders" && r.query.has("select")) return json([{ id: 1, user_id: "u1", total: 12 }]);
      if (rel === "/rest/v1/tasks" && r.query.has("select")) return json([]);
      if (rel === "/storage/v1/bucket") return json([]);
      if (rel === "/storage/v1/object/list/avatars") return json([{ name: "passport-scan.png" }]);
      if (rel === "/auth/v1/settings") return json({ mailer_autoconfirm: false });
      return json({ message: "Invalid API key" }, 401);
    });
  }

  it("finds the open table the bundle names, with the key the bundle holds", async () => {
    serve();
    const findings: ScanVulnerability[] = [];
    await runSupabaseProbes(bundle(), "deep", findings);
    const open = findings.find((f) => /Tables Readable Without Authentication/.test(f.name));
    expect(open?.severity).toBe("critical");
    expect(open?.evidence).toContain("orders");
    expect(open?.evidence).not.toContain("tasks");
    expect(serviceKeyNeverSent()).toBe(true);
  });

  it("lists a bucket the code names even though the bucket list itself is empty", async () => {
    serve();
    const findings: ScanVulnerability[] = [];
    await runSupabaseProbes(bundle(), "deep", findings);
    const files = findings.find((f) => /Storage Files Listable/.test(f.name));
    expect(files?.evidence).toContain("avatars");
    expect(files?.evidence).toContain("passport-scan.png");
  });

  it("does not send the service_role key when the bundle holds both keys", async () => {
    serve();
    const findings: ScanVulnerability[] = [];
    await runSupabaseProbes(bundle({ service: true }), "deep", findings);
    // The exposed key is reported, not used.
    const exposed = findings.find((f) => /Service Role Key Exposed/.test(f.name));
    expect(exposed?.severity).toBe("critical");
    expect(findings.find((f) => /Tables Readable Without Authentication/.test(f.name))).toBeDefined();
    expect(stub.requests.length).toBeGreaterThan(0);
    expect(serviceKeyNeverSent()).toBe(true);
  });

  it("finds nothing to test in a page whose bundle was not supplied", async () => {
    serve();
    const findings: ScanVulnerability[] = [];
    await runSupabaseProbes(`<html><body><div id="root"></div><script type="module" src="/assets/app.js"></script></body></html>`, "deep", findings);
    expect(findings).toEqual([]);
    expect(stub.requests).toHaveLength(0);
  });
});

describe("probeSupabaseStorageContents with bucket names from the code", () => {
  const LOCAL_BASE = () => `${stub.origin}${PREFIX}`;
  const list = (b: string) => `${PREFIX}/storage/v1/object/list/${b}`;

  function respond(routes: Record<string, unknown[]>, bucketListStatus = 200) {
    stub.onAny(new RegExp(`^${PREFIX}/storage/`), (r): Reply => {
      if (r.path === `${PREFIX}/storage/v1/bucket`) return json(bucketListStatus === 200 ? [] : { message: "nope" }, bucketListStatus);
      const hit = routes[r.path];
      return hit ? json(hit) : json({ message: "Bucket not found" }, 404);
    });
  }
  const run = async (hints: string[]) => {
    const out: ScanVulnerability[] = [];
    await probeSupabaseStorageContents(LOCAL_BASE(), ANON, out, hints);
    return out;
  };

  it("flags a hinted bucket whose files can be listed although the bucket list is empty", async () => {
    respond({ [list("avatars")]: [{ name: "invoice-1.pdf" }] });
    const out = await run(["avatars"]);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("invoice-1.pdf");
  });

  it("clean twin: a hinted bucket that lists nothing, or does not exist, is not a finding", async () => {
    respond({ [list("avatars")]: [] });
    expect(await run(["avatars", "ghost"])).toEqual([]);
  });

  it("still works from the bucket list alone, and when the list is refused", async () => {
    respond({ [list("docs")]: [{ name: "a.pdf" }] }, 401);
    expect(await run(["docs"])).toHaveLength(1);
    expect(await run([])).toEqual([]);
  });

  it("asks about a bucket once however often it is named, and at most five", async () => {
    respond({});
    await run(["a", "a", "b", "c", "d", "e", "f", "g"]);
    const asked = stub.requests.map((r) => r.path).filter((p) => p.includes("/object/list/"));
    expect(asked).toHaveLength(5);
    expect(new Set(asked).size).toBe(5);
  });
});

describe("checkSupabaseRLS given a page plus a bundle", () => {
  function serve(rowsByTable: Record<string, unknown[]>) {
    stub.onAny(new RegExp(`^${PREFIX}/`), (r): Reply => {
      const table = /\/rest\/v1\/([^/?]+)$/.exec(r.path)?.[1];
      if (table && r.query.has("select")) return json(rowsByTable[table] ?? []);
      return json({ definitions: { orders: {}, tasks: {} } });
    });
  }
  const page = `<html><body><div id="root"></div></body></html>`;

  it("tests the project a bundle names: open rows are critical", async () => {
    serve({ orders: [{ id: 1, user_id: "u1", total: 4 }] });
    const out = await checkSupabaseRLS(`${page}\n${bundle()}`);
    expect(out[0]!.severity).toBe("critical");
    expect(out[0]!.evidence).toContain("orders");
    expect(serviceKeyNeverSent()).toBe(true);
  });

  it("uses the anon key, not the service_role key, when the bundle holds both and the service key comes first", async () => {
    serve({ orders: [{ id: 1, user_id: "u1", total: 4 }] });
    const code = `const adm=cO("${BASE}","${SERVICE}");const sM="${BASE}",aM="${ANON}";`;
    const out = await checkSupabaseRLS(`${page}\n${code}`);
    expect(out[0]!.severity).toBe("critical");
    expect(stub.requests.length).toBeGreaterThan(0);
    expect(stub.requests.every((r) => JSON.stringify(r.headers).includes(ANON))).toBe(true);
  });

  it("makes no request when the bundle holds only a service_role key: it is reported elsewhere, never used", async () => {
    serve({ orders: [{ id: 1 }] });
    const out = await checkSupabaseRLS(`${page}\nconst adm=cO("${BASE}","${SERVICE}");`);
    expect(stub.requests).toHaveLength(0);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("info");
  });

  it("does not take an unrelated token elsewhere in the bundle for the key", async () => {
    serve({ orders: [{ id: 1 }] });
    const sample = jwt({ sub: "1234567890", name: "John Doe", iat: 1516239022 });
    const out = await checkSupabaseRLS(`const u="${BASE}";${VENDOR}${VENDOR}const docs="${sample}";`);
    expect(stub.requests).toHaveLength(0);
    expect(out[0]!.severity).toBe("info");
  });
});
