import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runFirebaseProbes } from "./firebase-probes.js";
import type { ScanVulnerability } from "./scanner";

const CONFIG_HTML = `
<script>
  const firebaseConfig = {
    apiKey: "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    projectId: "demo-project-1",
    databaseURL: "https://demo-project-1.firebaseio.com"
  };
</script>`;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetch(byUrl: (url: string) => Response) {
  vi.mocked(fetch).mockImplementation(async (input) => byUrl(String(input)));
}

describe("runFirebaseProbes — Realtime Database, regression: empty object", () => {
  it("does not flag a root that returns an empty object", async () => {
    // Real Firebase RTDB semantics essentially never produce a bare {} — a
    // path with no data returns null — but the check must not rely on that
    // assumption. Before the fix, `typeof body === "object"` was true for
    // {} exactly as it is for real data, so this case reported "open,
    // critical" for a database that returned nothing.
    mockFetch((url) => {
      if (url.includes("firebaseio.com")) return jsonResponse({});
      return jsonResponse({}); // no open Firestore collections
    });

    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);

    expect(findings.some((f) => /Realtime Database Open/i.test(f.name))).toBe(false);
  });

  it("still flags a root that returns real data", async () => {
    mockFetch((url) => {
      if (url.includes("firebaseio.com")) {
        return jsonResponse({ users: { u1: { email: "a@example.com" } } });
      }
      return jsonResponse({});
    });

    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);

    expect(findings.some((f) => /Realtime Database Open/i.test(f.name))).toBe(true);
  });

  it("does not flag a root that returns null (restrictive rules)", async () => {
    mockFetch((url) => {
      if (url.includes("firebaseio.com")) return jsonResponse(null);
      return jsonResponse({});
    });

    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);

    expect(findings.some((f) => /Realtime Database Open/i.test(f.name))).toBe(false);
  });
});

describe("runFirebaseProbes — Firestore (sanity: already correct before this pass)", () => {
  it("does not flag an accessible-but-empty collection", async () => {
    mockFetch((url) => {
      if (url.includes("firestore.googleapis.com")) return jsonResponse({ documents: [] });
      return jsonResponse(null); // RTDB restrictive
    });

    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);

    expect(findings.some((f) => /Firestore.*Unauthenticated Read/i.test(f.name))).toBe(false);
  });

  it("flags a collection that returns real documents", async () => {
    mockFetch((url) => {
      if (url.includes("firestore.googleapis.com") && url.includes("/users?")) {
        return jsonResponse({ documents: [{ name: "projects/demo/documents/users/u1" }] });
      }
      if (url.includes("firestore.googleapis.com")) return jsonResponse({ documents: [] });
      return jsonResponse(null);
    });

    const findings: ScanVulnerability[] = [];
    await runFirebaseProbes(CONFIG_HTML, findings);

    expect(findings.some((f) => /Firestore.*Unauthenticated Read/i.test(f.name))).toBe(true);
  });
});

describe("runFirebaseProbes — public-by-design Firestore collections", () => {
  const serveDocs = (byCollection: Record<string, unknown[]>) =>
    mockFetch((url) => {
      const m = /documents\/([a-z]+)\?/.exec(url);
      if (m) return jsonResponse({ documents: byCollection[m[1]!] ?? [] });
      return jsonResponse(null);
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
