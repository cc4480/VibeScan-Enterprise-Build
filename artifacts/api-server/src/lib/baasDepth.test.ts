import { describe, it, expect, vi, afterEach } from "vitest";
import { probeSupabaseAuth, probeSupabaseStorageContents, probeFirebaseStorage, extractStorageBucket } from "./baasDepth";
import type { ScanVulnerability } from "./scanner";

const BASE = "https://abc.supabase.co";
const KEY = "eyJ" + "a".repeat(60);

function respond(routes: Record<string, { status?: number; body?: unknown; text?: string }>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${url}`;
    const hit = routes[key];
    if (!hit) return new Response("not found", { status: 404 });
    return new Response(hit.text ?? JSON.stringify(hit.body ?? {}), { status: hit.status ?? 200 });
  }));
}
const run = async (f: (out: ScanVulnerability[]) => Promise<void>) => { const out: ScanVulnerability[] = []; await f(out); return out; };
afterEach(() => vi.unstubAllGlobals());

describe("Supabase Auth settings", () => {
  const url = `GET ${BASE}/auth/v1/settings`;
  it("flags open sign-up with email confirmation off", async () => {
    respond({ [url]: { body: { mailer_autoconfirm: true, disable_signup: false } } });
    const out = await run((o) => probeSupabaseAuth(BASE, KEY, o));
    expect(out.map((f) => f.name)).toEqual(["Supabase Email Confirmation Disabled"]);
  });
  it("clean twin: confirmation on", async () => {
    respond({ [url]: { body: { mailer_autoconfirm: false, disable_signup: false } } });
    expect(await run((o) => probeSupabaseAuth(BASE, KEY, o))).toEqual([]);
  });
  it("silent when sign-ups are disabled, when the setting is absent, on errors and on junk", async () => {
    for (const r of [
      { body: { mailer_autoconfirm: true, disable_signup: true } },
      { body: { external: { email: true } } },
      { status: 401, body: { mailer_autoconfirm: true } },
      { text: "<html>nope</html>" },
    ]) {
      respond({ [url]: r });
      expect(await run((o) => probeSupabaseAuth(BASE, KEY, o))).toEqual([]);
    }
  });
});

describe("Supabase Storage contents", () => {
  const listBuckets = `GET ${BASE}/storage/v1/bucket`;
  const listObjects = (b: string) => `POST ${BASE}/storage/v1/object/list/${b}`;
  it("flags a bucket whose files the anon key can list, naming the bucket and a file", async () => {
    respond({ [listBuckets]: { body: [{ name: "docs" }] }, [listObjects("docs")]: { body: [{ name: "invoice-1.pdf" }] } });
    const out = await run((o) => probeSupabaseStorageContents(BASE, KEY, o));
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
    expect(await run((o) => probeSupabaseStorageContents(BASE, KEY, o))).toEqual([]);
  });
  it("silent when the bucket list itself is not readable", async () => {
    respond({ [listBuckets]: { status: 401, body: { message: "unauthorized" } } });
    expect(await run((o) => probeSupabaseStorageContents(BASE, KEY, o))).toEqual([]);
  });
  it("makes no more than five listing requests", async () => {
    const buckets = Array.from({ length: 12 }, (_, i) => ({ name: `b${i}` }));
    respond({ [listBuckets]: { body: buckets } });
    await run((o) => probeSupabaseStorageContents(BASE, KEY, o));
    const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.filter((c) => String(c[0]).includes("/object/list/"));
    expect(calls).toHaveLength(5);
  });
});

describe("Firebase Storage", () => {
  const page = `firebase.initializeApp({ apiKey: "x", storageBucket: "my-app.appspot.com" })`;
  const url = "GET https://firebasestorage.googleapis.com/v0/b/my-app.appspot.com/o?maxResults=5";
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
  });
  it("clean twin: rules deny the listing", async () => {
    respond({ [url]: { status: 403, body: { error: { code: 403, message: "Permission denied." } } } });
    expect(await run((o) => probeFirebaseStorage(page, o))).toEqual([]);
  });
  it("silent for an empty bucket, for an unparsable body and when the page has no bucket", async () => {
    respond({ [url]: { body: {} } });
    expect(await run((o) => probeFirebaseStorage(page, o))).toEqual([]);
    respond({ [url]: { text: "oops" } });
    expect(await run((o) => probeFirebaseStorage(page, o))).toEqual([]);
    expect(await run((o) => probeFirebaseStorage("nothing", o))).toEqual([]);
  });
});
