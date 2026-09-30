import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// probes.ts reaches the network through scanFetch; the Supabase probes use global fetch.
const scanFetchMock = vi.fn();
vi.mock("./http.js", () => ({ scanFetch: (...a: unknown[]) => scanFetchMock(...a) }));

import { runSupabaseProbes } from "./supabase-probes.js";
import { checkSupabaseRLS } from "./probes.js";
import { classifyExposure } from "./baasExposure.js";

/** role: "anon" — public by design. */
const ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
  ".eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE5NjAwMDAwMDB9" +
  ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const page = (table: string) => `<script>
  const supabase = createClient('https://abcdefgh.supabase.co', '${ANON_KEY}');
  supabase.from("${table}").select("*");
</script>`;

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });

/** Routes: read (?select=) and write (POST) answers; everything else is the locked spec endpoint. */
function stubServer(read: () => Response, write: () => Response) {
  vi.mocked(fetch).mockImplementation((input, init) => {
    const url = String(input);
    if (url.includes("?select=")) return Promise.resolve(read());
    if ((init as RequestInit | undefined)?.method === "POST" && url.includes("/rest/v1/")) {
      return Promise.resolve(write());
    }
    return Promise.resolve(json({ message: "Invalid API key" }, 401));
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
  scanFetchMock.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

const run = async (table: string) => {
  const findings: any[] = [];
  await runSupabaseProbes(page(table), "deep", findings);
  return findings;
};

describe("Supabase probes — RLS-protected table answering 200 []", () => {
  it("is not a vulnerability (clean twin)", async () => {
    stubServer(() => json([]), () => json({ code: "42501", message: "new row violates row-level security policy" }, 401));
    const findings = await run("notes");
    expect(findings.filter((f) => ["critical", "high", "medium"].includes(f.severity))).toEqual([]);
    const empty = findings.find((f) => /Empty Results/.test(f.name));
    expect(empty?.severity).toBe("info");
    expect(empty.description).toMatch(/enabled and no anon policy/);
  });
});

describe("Supabase probes — public catalogue tables", () => {
  it("a products table with catalogue columns is INFO, not CRITICAL", async () => {
    stubServer(() => json([{ id: 1, name: "Mug", price: 12, image_url: "/m.png" }]), () => json({}, 401));
    const findings = await run("products");
    expect(findings.find((f) => f.severity === "critical")).toBeUndefined();
    const f = findings.find((x) => /Public Content Tables/.test(x.name));
    expect(f?.severity).toBe("info");
    expect(f.evidence).toContain("name, price");
  });

  it("still CRITICAL for a sensitive table name", async () => {
    stubServer(() => json([{ id: 1, total: 12 }]), () => json({}, 401));
    const findings = await run("orders");
    expect(findings.find((f) => f.severity === "critical" && /CVE-2025-48757/.test(f.name))).toBeDefined();
  });

  it("still CRITICAL for a public-sounding table that carries personal columns", async () => {
    stubServer(() => json([{ id: 1, title: "x", author_email: "a@b.co" }]), () => json({}, 401));
    const findings = await run("posts");
    expect(findings.find((f) => f.severity === "critical")).toBeDefined();
  });

  it("classifies names and rows", () => {
    expect(classifyExposure("faq", [{ q: "a" }])).toBe("public");
    expect(classifyExposure("blog_posts", [{ title: "a" }])).toBe("public");
    expect(classifyExposure("user_settings", [{ a: 1 }])).toBe("sensitive");
    expect(classifyExposure("config", [{ stripe: "sk_live_abcdefghijklmnop" }])).toBe("sensitive");
    expect(classifyExposure("notes", [{ a: 1 }])).toBe("unclassified");
  });
});

describe("Supabase probes — write probe", () => {
  it("a 400 unknown-column answer is not 'writes accepted' (clean twin)", async () => {
    stubServer(() => json([]), () => json({ code: "PGRST204", message: "Could not find the '__vibescan_probe__' column" }, 400));
    const findings = await run("notes");
    expect(findings.find((f) => /Accept Unauthenticated Writes/.test(f.name))).toBeUndefined();
    const f = findings.find((x) => /Write Access Not Confirmed/.test(x.name));
    expect(f?.severity).toBe("info");
    expect(f.evidence).toContain("PGRST204");
  });

  it("a 201 (row really inserted, then deleted) is still CRITICAL", async () => {
    stubServer(
      () => json([]),
      () => json([{ id: 7 }], 201),
    );
    const findings = await run("notes");
    const f = findings.find((x) => /Accept Unauthenticated Writes/.test(x.name));
    expect(f?.severity).toBe("critical");
    expect(f.evidence).toMatch(/HTTP 2xx/);
  });
});

describe("checkSupabaseRLS (probes.ts)", () => {
  const html = (extra = "") =>
    `<script>const u="https://abcdefghijklmnopqrst.supabase.co"; const anonKey="${ANON_KEY}";${extra}</script>`;
  const spec = { definitions: { products: {}, orders: {} } };

  function serve(rowsByTable: Record<string, unknown[]>) {
    scanFetchMock.mockImplementation(async (url: string) => {
      const m = /\/rest\/v1\/([^?]+)\?select/.exec(url);
      if (m) return { status: 200, body: JSON.stringify(rowsByTable[m[1]!] ?? []), headers: {} };
      return { status: 200, body: JSON.stringify(spec), headers: {} };
    });
  }

  it("no key in the page: unobserved, so INFO low confidence, never MEDIUM 6.5", async () => {
    const out = await checkSupabaseRLS(`<script>fetch("https://abcdefghijklmnopqrst.supabase.co/rest/v1/x")</script>`);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("info");
    expect(out[0]!.cvssScore).toBe(0);
    expect(out[0]!.confidence).toBeLessThan(50);
    expect(scanFetchMock).not.toHaveBeenCalled();
  });

  it("public catalogue rows are INFO (clean twin)", async () => {
    serve({ products: [{ id: 1, name: "Mug", price: 3 }] });
    const out = await checkSupabaseRLS(html());
    expect(out.find((v) => v.severity === "critical")).toBeUndefined();
    expect(out[0]!.severity).toBe("info");
  });

  it("rows from a sensitive table are still CRITICAL", async () => {
    serve({ orders: [{ id: 1, total: 3 }] });
    const out = await checkSupabaseRLS(html());
    expect(out[0]!.severity).toBe("critical");
    expect(out[0]!.evidence).toContain("orders");
  });
});
