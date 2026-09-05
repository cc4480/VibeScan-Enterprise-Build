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
