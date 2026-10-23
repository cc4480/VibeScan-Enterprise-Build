import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { runSupabaseProbes } from "./supabase-probes.js";
import { startBaasStub, useRealBaas, type BaasStub, type Reply } from "./baasStub.testkit";

/**
 * VibeStack Supabase probe tests.
 * These are VibeScan's most important differentiating feature —
 * detecting exposed Supabase RLS misconfigurations in AI-built apps.
 *
 * The probes make their real requests to a local server that answers like a Supabase project (lib/baasStub.testkit.ts).
 */

// ─── JWT fixtures ─────────────────────────────────────────────────────────────

/**
 * Valid anon key JWT (role: "anon") — public by design, not a vulnerability.
 * Payload: {"role":"anon","iss":"supabase","iat":1600000000,"exp":1960000000}
 */
const ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
  ".eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE5NjAwMDAwMDB9" +
  ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/**
 * service_role JWT — bypasses ALL RLS, critical if exposed client-side.
 * Payload: {"role":"service_role","iss":"supabase","iat":1600000000,"exp":1960000000}
 */
const SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
  ".eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE2MDAwMDAwMDAsImV4cCI6MTk2MDAwMDAwMH0" +
  ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// ─── HTML fixture helpers ─────────────────────────────────────────────────────

/** Anon key via createClient — extracted by the first keyPattern regex. */
function htmlWithAnonKey(): string {
  return `<script>
    const supabase = createClient(
      'https://abcdefgh.supabase.co',
      '${ANON_KEY}'
    )
  </script>`;
}

/** service_role key via a recognised variable name. */
function htmlWithServiceRoleKey(): string {
  return `<script>
    const SUPABASE_SERVICE_ROLE_KEY = '${SERVICE_ROLE_KEY}'
    const supabase = createClient('https://abcdefgh.supabase.co', SUPABASE_SERVICE_ROLE_KEY)
  </script>`;
}

function htmlWithNoSupabase(): string {
  return `<html><body>Hello world — no Supabase here</body></html>`;
}

// ─── The local Supabase-like server ────────────────────────────────────────────

let stub: BaasStub;
beforeAll(async () => { stub = await startBaasStub(); });
afterAll(async () => { await stub.stop(); useRealBaas(); });
beforeEach(() => stub.clear());

function jsonResponse(data: unknown, status = 200): Reply {
  return { json: data, status };
}

/** Answers every request to the project from `impl(url)`, where url is the path and query as received. */
function answerWith(impl: (url: string) => Reply) {
  stub.onAny(/^\/supabase\//, (r) => impl(r.url));
}

// ─── service_role key detection (no HTTP needed for the finding itself) ───────

describe("runSupabaseProbes — service_role key in client code", () => {
  it("reports CRITICAL finding when service_role key is in client-side HTML", async () => {
    // After detecting the service_role key the probe still tries to probe tables;
    // mock subsequent HTTP calls so they return nothing meaningful.
    answerWith(() => jsonResponse({ message: "Not found" }, 404));

    const findings: any[] = [];
    await runSupabaseProbes(htmlWithServiceRoleKey(), "deep", findings);

    const critical = findings.find(
      (f) => f.severity === "critical" && /service.role/i.test(f.name),
    );
    expect(critical).toBeDefined();
    expect(critical.cvssScore).toBe(10.0);
    expect(critical.cweId).toBe("CWE-522");
  });

  it("does NOT report service_role vuln when only the anon key is present", async () => {
    answerWith(() => jsonResponse([], 200));

    const findings: any[] = [];
    await runSupabaseProbes(htmlWithAnonKey(), "deep", findings);

    const critical = findings.find(
      (f) => f.severity === "critical" && /service.role/i.test(f.name),
    );
    expect(critical).toBeUndefined();
  });
});

// ─── No Supabase detected ────────────────────────────────────────────────────

describe("runSupabaseProbes — no Supabase in content", () => {
  it("returns no findings and makes no HTTP calls when Supabase is not present", async () => {
    const findings: any[] = [];
    await runSupabaseProbes(htmlWithNoSupabase(), "deep", findings);

    expect(findings).toHaveLength(0);
    expect(stub.requests).toHaveLength(0);
  });
});

// ─── RLS probe via REST API ───────────────────────────────────────────────────

describe("runSupabaseProbes — RLS checks via REST API", () => {
  it("reports informational finding when Supabase detected but tables not enumerable", async () => {
    // OpenAPI spec returns valid JSON but with no paths/definitions → no tables
    answerWith(() => jsonResponse({}, 200));

    const findings: any[] = [];
    await runSupabaseProbes(htmlWithAnonKey(), "deep", findings);

    const infoFinding = findings.find((f) => /supabase/i.test(f.name));
    expect(infoFinding).toBeDefined();
  });

  it("reports finding when a table returns rows without authentication (RLS disabled)", async () => {
    // Spec with one table in `definitions`
    const openApiSpec = {
      definitions: {
        users: { properties: { id: { format: "bigint" }, email: { format: "text" } } },
      },
    };

    answerWith((url) => {
      // Table read: returns array of rows → "open" read result
      if (url.includes("?select=")) {
        return jsonResponse([{ id: 1, email: "user@example.com" }], 200);
      }
      // Write probe: return 401 so it's treated as "protected" (no write finding)
      if (url.includes("/rest/v1/users") && !url.includes("?")) {
        return jsonResponse({ message: "Unauthorized" }, 401);
      }
      // /rest/v1/ (OpenAPI spec endpoint)
      return jsonResponse(openApiSpec, 200);
    });

    const findings: any[] = [];
    await runSupabaseProbes(htmlWithAnonKey(), "deep", findings);

    // "Supabase Tables Readable Without Authentication (CVE-2025-48757)"
    const rlsFinding = findings.find(
      (f) =>
        (f.severity === "critical" || f.severity === "high") &&
        /readable.*auth|CVE-2025-48757/i.test(f.name),
    );
    expect(rlsFinding).toBeDefined();
    expect(rlsFinding.cweId).toBeTruthy();
  });

  /**
   * Verified live against a real, freshly-created Supabase project
   * (2026-09-20), not assumed: GET /rest/v1/ with an anon key now returns
   * {"message":"Invalid API key","hint":"Only the `service_role` API key can
   * be used for this endpoint."} on current Supabase, where it used to return
   * the OpenAPI-shaped schema this probe enumerates tables from. That endpoint
   * is the ONLY thing enumerateSupabaseTables() reads, so this is not a fixture
   * edge case — it is what every current Supabase project does, and it made
   * this exact CVE undetectable until the table name was also read out of the
   * bundle's own `.from()` calls.
   */
  it("finds the open table from .from() calls when REST enumeration is locked to service_role", async () => {
    answerWith((url) => {
      if (url.includes("?select=")) {
        // A per-user row (it carries an owner column). Rows with nothing personal or per-user in them are
        // reported as information, not critical: see supabase-exposure.test.ts.
        return jsonResponse([{ id: 1, content: "exposed row", user_id: "u-1" }], 200);
      }
      if (url.includes("/rest/v1/notes") && !url.includes("?")) {
        return jsonResponse({ message: "Unauthorized" }, 401); // write: protected
      }
      // The real, current Supabase response for an anon key at this endpoint.
      return jsonResponse(
        { message: "Invalid API key", hint: "Only the `service_role` API key can be used for this endpoint." },
        401,
      );
    });

    const html = `<script>
      const supabase = createClient('https://abcdefgh.supabase.co', '${ANON_KEY}');
      async function loadNotes() {
        const { data } = await supabase.from("notes").select("*");
        return data;
      }
    </script>`;

    const findings: any[] = [];
    await runSupabaseProbes(html, "deep", findings);

    const rlsFinding = findings.find(
      (f) => f.severity === "critical" && /readable.*auth|CVE-2025-48757/i.test(f.name),
    );
    expect(rlsFinding).toBeDefined();
    expect(rlsFinding.evidence).toContain("notes");

    // Must not have fallen back to the harmless "detected but not enumerable"
    // note — that is exactly the silent miss this test exists to catch.
    const infoOnly = findings.find((f) => f.name === "Supabase Backend Detected");
    expect(infoOnly).toBeUndefined();
  });

  it("still reports the informational finding when neither REST enumeration nor .from() calls find a table name", async () => {
    answerWith(() => jsonResponse({ message: "Invalid API key" }, 401));

    // No .from(...) call anywhere in this bundle — genuinely nothing to test.
    const html = `<script>
      const supabase = createClient('https://abcdefgh.supabase.co', '${ANON_KEY}');
    </script>`;

    const findings: any[] = [];
    await runSupabaseProbes(html, "deep", findings);

    expect(findings.find((f) => f.name === "Supabase Backend Detected")).toBeDefined();
    expect(findings.find((f) => f.severity === "critical")).toBeUndefined();
  });
});
