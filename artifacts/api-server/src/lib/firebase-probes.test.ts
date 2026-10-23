import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { runFirebaseProbes } from "./firebase-probes.js";
import { startBaasStub, useRealBaas, type BaasStub, type Reply } from "./baasStub.testkit";
import type { ScanVulnerability } from "./scanner";

// The probes make their real requests to a local server that answers like Firebase (lib/baasStub.testkit.ts):
// /rtdb/<name>/... is the Realtime Database, /firestore/... is Cloud Firestore.
let stub: BaasStub;
beforeAll(async () => { stub = await startBaasStub(); });
afterAll(async () => { await stub.stop(); useRealBaas(); });
beforeEach(() => stub.clear());

const CONFIG_HTML = `
<script>
  const firebaseConfig = {
    apiKey: "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    projectId: "demo-project-1",
    databaseURL: "https://demo-project-1.firebaseio.com"
  };
</script>`;

const json = (body: unknown, status = 200): Reply => ({ json: body, status });

/** Answers the Realtime Database from `rtdb` and Firestore (by request URL) from `firestore`. */
function serve(rtdb: Reply, firestore: Reply | ((url: string) => Reply)) {
  stub.onAny(/^\/rtdb\//, rtdb);
  stub.onAny(/^\/firestore\//, (r) => (typeof firestore === "function" ? firestore(r.url) : firestore));
}

describe("runFirebaseProbes: Realtime Database, regression: empty object", () => {
  it("does not flag a root that returns an empty object", async () => {
    // Real Firebase RTDB semantics essentially never produce a bare {}: a path with no data returns null. But the
    // check must not rely on that assumption. Before the fix, `typeof body === "object"` was true for {} exactly as it
    // is for real data, so this case reported "open, critical" for a database that returned nothing.
    serve(json({}), json({})); // no open Firestore collections
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(stub.requests.some((r) => r.path === "/rtdb/demo-project-1/.json")).toBe(true); // it really asked
    expect(findings.some((f) => /Realtime Database Open/i.test(f.name))).toBe(false);
  });

  it("still flags a root that returns real data", async () => {
    serve(json({ users: { u1: { email: "a@example.com" } } }), json({}));
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(findings.some((f) => /Realtime Database Open/i.test(f.name))).toBe(true);
  });

  it("does not flag a root that returns null (restrictive rules)", async () => {
    serve(json(null), json({}));
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(findings.some((f) => /Realtime Database Open/i.test(f.name))).toBe(false);
  });
});

describe("runFirebaseProbes: Firestore (sanity: already correct before this pass)", () => {
  it("does not flag an accessible-but-empty collection", async () => {
    serve(json(null), json({ documents: [] })); // RTDB restrictive
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(stub.requests.some((r) => r.path.startsWith("/firestore/v1/projects/demo-project-1/"))).toBe(true);
    expect(findings.some((f) => /Firestore.*Unauthenticated Read/i.test(f.name))).toBe(false);
  });

  it("flags a collection that returns real documents", async () => {
    serve(json(null), (url) => (url.includes("/users?") ? json({ documents: [{ name: "projects/demo/documents/users/u1" }] }) : json({ documents: [] })));
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(findings.some((f) => /Firestore.*Unauthenticated Read/i.test(f.name))).toBe(true);
  });
});

describe("runFirebaseProbes: public-by-design Firestore collections", () => {
  const serveDocs = (byCollection: Record<string, unknown[]>) =>
    serve(json(null), (url) => {
      const m = /documents\/([a-z]+)\?/.exec(url);
      return m ? json({ documents: byCollection[m[1]!] ?? [] }) : json(null);
    });
  const flagged = (fs: ScanVulnerability[]) => fs.find((f) => /Rules Allow Unauthenticated Read/i.test(f.name));

  it("a posts collection of public content is INFO, not CRITICAL (clean twin)", async () => {
    serveDocs({ posts: [{ name: "projects/demo/databases/(default)/documents/posts/p1", fields: { title: { stringValue: "Hello" }, body: { stringValue: "World" } } }] });
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(flagged(findings)).toBeUndefined();
    const info = findings.find((f) => /Public Content Collection/.test(f.name));
    expect(info?.severity).toBe("info");
  });

  it("a readable users collection is still CRITICAL even when posts is also readable", async () => {
    serveDocs({
      posts: [{ fields: { title: { stringValue: "Hello" } } }],
      users: [{ name: "projects/demo/databases/(default)/documents/users/u1" }],
    });
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(flagged(findings)?.severity).toBe("critical");
    expect(flagged(findings)?.evidence).toContain("Open collection: users");
  });

  it("a config collection holding a secret is still CRITICAL", async () => {
    serveDocs({ config: [{ fields: { stripeSecret: { stringValue: "sk_live_abcdefghijklmnop" } } }] });
    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);
    expect(flagged(findings)?.severity).toBe("critical");
  });
});
