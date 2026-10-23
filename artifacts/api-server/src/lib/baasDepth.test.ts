import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { probeSupabaseAuth, probeSupabaseStorageContents, probeFirebaseStorage, extractStorageBucket } from "./baasDepth";
import { startBaasStub, useRealBaas, type BaasStub } from "./baasStub.testkit";
import type { ScanVulnerability } from "./scanner";

// The probes make their real requests to a local server that answers like Supabase and Firebase Storage
// (lib/baasStub.testkit.ts).
let stub: BaasStub;
beforeAll(async () => { stub = await startBaasStub(); });
afterAll(async () => { await stub.stop(); useRealBaas(); });
beforeEach(() => stub.clear());

const PFX = "/supabase/abc";
const KEY = "eyJ" + "a".repeat(60);
/** What the probes are told the project's address is; it leads to the local server. */
const base = () => `${stub.origin}${PFX}`;

/** Answer each "METHOD path" from the table; anything else is a 404. */
function respond(routes: Record<string, { status?: number; body?: unknown; text?: string }>) {
  stub.onAny(/./, (r) => {
    const hit = routes[`${r.method} ${r.path}`];
    if (!hit) return { status: 404, text: "not found" };
    return hit.text !== undefined ? { status: hit.status ?? 200, text: hit.text } : { status: hit.status ?? 200, json: hit.body ?? {} };
  });
}
const run = async (f: (out: ScanVulnerability[]) => Promise<void>) => { const out: ScanVulnerability[] = []; await f(out); return out; };

describe("Supabase Auth settings", () => {
  const url = `GET ${PFX}/auth/v1/settings`;
  it("flags open sign-up with email confirmation off", async () => {
    respond({ [url]: { body: { mailer_autoconfirm: true, disable_signup: false } } });
    const out = await run((o) => probeSupabaseAuth(base(), KEY, o));
    expect(out.map((f) => f.name)).toEqual(["Supabase Email Confirmation Disabled"]);
    expect(stub.requests[0]!.headers["apikey"]).toBe(KEY);
  });
  it("clean twin: confirmation on", async () => {
    respond({ [url]: { body: { mailer_autoconfirm: false, disable_signup: false } } });
    expect(await run((o) => probeSupabaseAuth(base(), KEY, o))).toEqual([]);
  });
  it("silent when sign-ups are disabled, when the setting is absent, on errors and on junk", async () => {
    for (const r of [
      { body: { mailer_autoconfirm: true, disable_signup: true } },
      { body: { external: { email: true } } },
      { status: 401, body: { mailer_autoconfirm: true } },
      { text: "<html>nope</html>" },
    ]) {
      stub.clear();
      respond({ [url]: r });
      expect(await run((o) => probeSupabaseAuth(base(), KEY, o))).toEqual([]);
    }
  });
});

describe("Supabase Storage contents", () => {
  const listBuckets = `GET ${PFX}/storage/v1/bucket`;
  const listObjects = (b: string) => `POST ${PFX}/storage/v1/object/list/${b}`;
  it("flags a bucket whose files the anon key can list, naming the bucket and a file", async () => {
    respond({ [listBuckets]: { body: [{ name: "docs" }] }, [listObjects("docs")]: { body: [{ name: "invoice-1.pdf" }] } });
    const out = await run((o) => probeSupabaseStorageContents(base(), KEY, o));
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("docs");
    expect(out[0]!.evidence).toContain("invoice-1.pdf");
  });
  it("clean twin: buckets exist but listing their files is denied or empty", async () => {
    respond({
      [listBuckets]: { body: [{ name: "docs" }, { name: "avatars" }] },
      [listObjects("docs")]: { status: 400, body: { message: "new row violates row-level security policy" } },
      [listObjects("avatars")]: { body: [] },
    });
    expect(await run((o) => probeSupabaseStorageContents(base(), KEY, o))).toEqual([]);
  });
  it("silent when the bucket list itself is not readable", async () => {
    respond({ [listBuckets]: { status: 401, body: { message: "unauthorized" } } });
    expect(await run((o) => probeSupabaseStorageContents(base(), KEY, o))).toEqual([]);
  });
  it("makes no more than five listing requests", async () => {
    const buckets = Array.from({ length: 12 }, (_, i) => ({ name: `b${i}` }));
    respond({ [listBuckets]: { body: buckets } });
    await run((o) => probeSupabaseStorageContents(base(), KEY, o));
    expect(stub.requests.filter((r) => r.path.includes("/object/list/"))).toHaveLength(5);
  });
});

describe("Firebase Storage", () => {
  const page = `firebase.initializeApp({ apiKey: "x", storageBucket: "my-app.appspot.com" })`;
  const url = "GET /fbstorage/v0/b/my-app.appspot.com/o";
  it("reads the bucket name from the public config", () => {
    expect(extractStorageBucket(page)).toBe("my-app.appspot.com");
    expect(extractStorageBucket("no config here")).toBeNull();
  });
  it("flags a bucket that lists files to anyone", async () => {
    respond({ [url]: { body: { items: [{ name: "users/1/passport.jpg" }] } } });
    const out = await run((o) => probeFirebaseStorage(page, o));
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.evidence).toContain("users/1/passport.jpg");
    expect(stub.requests[0]!.query.get("maxResults")).toBe("5");
  });
  it("clean twin: rules deny the listing", async () => {
    respond({ [url]: { status: 403, body: { error: { code: 403, message: "Permission denied." } } } });
    expect(await run((o) => probeFirebaseStorage(page, o))).toEqual([]);
  });
  it("silent for an empty bucket, for an unparsable body and when the page has no bucket", async () => {
    respond({ [url]: { body: {} } });
    expect(await run((o) => probeFirebaseStorage(page, o))).toEqual([]);
    stub.clear();
    respond({ [url]: { text: "oops" } });
    expect(await run((o) => probeFirebaseStorage(page, o))).toEqual([]);
    expect(await run((o) => probeFirebaseStorage("nothing", o))).toEqual([]);
  });
});
