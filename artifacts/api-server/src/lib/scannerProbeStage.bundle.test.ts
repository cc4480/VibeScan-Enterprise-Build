import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { startBaasStub, useRealBaas, type BaasStub, type Reply } from "./baasStub.testkit";
import { useDohStub } from "./dohStub.testkit";
import { useHstsPreloadStub } from "./hstsPreloadStub.testkit";
import { startOsvStub } from "./osvStub.testkit";
import { runProbeStage } from "./scannerProbeStage";
import { TestLedger } from "./testLedger";

/**
 * The probe stage hands the site's downloaded JavaScript to the checks that look for a backend.
 *
 * Found with a Lovable-style target app (React + Vite, Supabase): its page is an empty shell and one
 * `<script type="module">`, and the project URL, the key and the table names are all in that script. The
 * Supabase, BaaS and storage checks were given only the page, so each answered "nothing to test" and
 * the target scored 2 of 10 faults with two tables readable by anyone. The stage already downloaded
 * the same script for the secret scanner; it just never passed it on.
 *
 * The whole stage runs for real. The target is a real web server serving the shell and the script; the Supabase project
 * is a real server that answers like one (lib/baasStub.testkit.ts), as are the DNS, HSTS-preload and advisory services
 * the stage also asks. What shows the script reached a check is what that check then asked the Supabase project.
 *
 * Not covered: how many times the script is downloaded (the stage's own checks each fetch what they need, so the count
 * is not a property of the hand-over), and the two cases that made the secret scanner fail or miss a key the Supabase
 * check saw, which cannot be produced with a real scanner that reads the same script.
 */

const REF = "abcdefghijklmnopqrst";
const PREFIX = `/supabase/${REF}`;
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${"s".repeat(43)}`;
const ANON = jwt({ iss: "supabase", ref: REF, role: "anon", iat: 1700000000, exp: 2000000000 });
const SERVICE = jwt({ iss: "supabase", ref: REF, role: "service_role", iat: 1700000000, exp: 2000000000 });

const SHELL = `<html><head><script type="module" crossorigin src="/assets/index-Ct6cDlio.js"></script></head><body><div id="root"></div></body></html>`;
const BUNDLE = `const sM="https://${REF}.supabase.co",aM="${ANON}",Tn=cO(sM,aM);Tn.from("orders");Tn.storage.from("avatars");`;
const BUNDLE_WITH_SERVICE_KEY = `${BUNDLE}const adm=cO(sM,"${SERVICE}");`;

await useDohStub();
await useHstsPreloadStub();
const osv = await startOsvStub();

let supabase: BaasStub;
const site = { script: BUNDLE as string | null, requested: [] as string[] };
const siteServer = http.createServer((req, res) => {
  site.requested.push(req.url ?? "");
  if (req.url === "/") { res.writeHead(200, { "content-type": "text/html" }).end(SHELL); return; }
  if (req.url === "/assets/index-Ct6cDlio.js") {
    if (site.script === null) { res.writeHead(500).end("error"); return; }
    res.writeHead(200, { "content-type": "text/javascript" }).end(site.script);
    return;
  }
  res.writeHead(404).end("not found");
});
await new Promise<void>((r) => siteServer.listen(0, "127.0.0.1", r));
const URL_ = `http://127.0.0.1:${(siteServer.address() as AddressInfo).port}/`;

beforeAll(async () => {
  supabase = await startBaasStub();
  // The project: anon reads of `orders` return rows (no row-level security), and a bucket lists a file.
  supabase.onAny(new RegExp(`^${PREFIX}/`), (r): Reply => {
    const rel = r.path.slice(PREFIX.length);
    if (rel === "/rest/v1/orders" && r.query.has("select")) return { json: [{ id: 1, user_id: "u1", total: 12 }] };
    if (rel === "/storage/v1/bucket") return { json: [] };
    if (rel === "/storage/v1/object/list/avatars") return { json: [{ name: "passport-scan.png" }] };
    if (rel === "/auth/v1/settings") return { json: { mailer_autoconfirm: false } };
    return { status: 401, json: { message: "Invalid API key" } };
  });
});
afterAll(async () => {
  await supabase.stop();
  useRealBaas();
  await osv.stop();
  siteServer.closeAllConnections();
  await new Promise<void>((r) => siteServer.close(() => r()));
});
beforeEach(() => {
  site.script = BUNDLE;
  site.requested.length = 0;
  supabase.requests.length = 0;
});

const stage = (allowActiveProbes: boolean) =>
  runProbeStage({
    finalUrl: URL_, html: SHELL, rawHeaders: {}, setCookies: [], status: 200, tier: "deep",
    allowActiveProbes, ledger: new TestLedger(), crawlPageBudget: 0,
  });
const names = (r: { vulnerabilities: Array<{ name: string }> }) => r.vulnerabilities.map((v) => v.name);
const askedProject = () => supabase.requests.map((q) => `${q.method} ${q.path.slice(PREFIX.length)}`);

describe("runProbeStage with active checks allowed", () => {
  it("gives the page plus the site's scripts to the Supabase check, which then finds the open table", async () => {
    const r = await stage(true);
    expect(site.requested).toContain("/assets/index-Ct6cDlio.js");
    // The project URL, key and table name exist only in the script; the check read them from there.
    expect(names(r)).toContain("Supabase Tables Readable Without Authentication (CVE-2025-48757)");
    const read = supabase.requests.find((q) => q.method === "GET" && q.path === `${PREFIX}/rest/v1/orders` && q.query.has("select"));
    expect(read).toBeDefined();
    expect(JSON.stringify(read!.headers)).toContain(ANON);
  });

  it("gives them to the cloud-storage check, which lists the bucket the script opens", async () => {
    const r = await stage(true);
    expect(askedProject()).toContain("POST /storage/v1/object/list/avatars");
    expect(names(r)).toContain("Supabase Storage Files Listable Without Authentication");
  });

  it("gives them to the Supabase RLS check inside the HTTP probes", async () => {
    await stage(true);
    // The row-level-security probe reads the table with a limit of one row.
    expect(supabase.requests.some((q) => q.method === "GET" && q.path === `${PREFIX}/rest/v1/orders` && q.query.get("limit") === "1")).toBe(true);
  });

  it("still runs the checks, on the page alone, when the scripts cannot be downloaded", async () => {
    site.script = null;
    const r = await stage(true);
    // The page names no project, so nothing is asked of one, and the stage still completes with the checks that need only the page.
    expect(askedProject()).toEqual([]);
    expect(names(r).some((n) => /Supabase/.test(n))).toBe(false);
    expect(names(r)).toContain("Missing security.txt (RFC 9116)");
  });
});

describe("runProbeStage without active checks (a target the user has not verified)", () => {
  it("starts none of the backend checks, although the script is on the site", async () => {
    // The passive checks still read the site's own files; what must not happen is a single request to the project it names.
    const r = await stage(false);
    expect(supabase.requests).toEqual([]);
    expect(names(r).some((n) => /Supabase/.test(n))).toBe(false);
  });
});

describe("a leaked service_role key is reported once", () => {
  const KEY_FINDINGS = /Service Role Key/;

  it("keeps the secret scanner's finding (it says which script held the key) and drops the Supabase check's", async () => {
    site.script = BUNDLE_WITH_SERVICE_KEY;
    const r = await stage(true);
    expect(names(r).filter((n) => KEY_FINDINGS.test(n))).toEqual(["Supabase Service Role Key Exposed in JavaScript"]);
    // And whatever else is asked of the project, the leaked key is never the one it is asked with.
    expect(supabase.requests.every((q) => !JSON.stringify(q.headers).includes(SERVICE))).toBe(true);
  });

  it("reports no key finding for a script that holds only the public anon key", async () => {
    const r = await stage(true);
    expect(names(r).filter((n) => KEY_FINDINGS.test(n))).toEqual([]);
  });
});
