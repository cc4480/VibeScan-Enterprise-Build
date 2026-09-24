import { describe, it, expect } from "vitest";
import { detectAgentEnvironment } from "./deepseek.js";

describe("detectAgentEnvironment", () => {
  it("detects Lovable by tech prefix", () => {
    expect(detectAgentEnvironment(["Lovable 2.0", "React"], "https://myapp.com")).toBe("lovable");
  });

  it("detects Lovable by .lovable.app hostname", () => {
    expect(detectAgentEnvironment([], "https://my-app.lovable.app")).toBe("lovable");
  });

  it("detects Lovable by .gptengineer.app hostname", () => {
    expect(detectAgentEnvironment([], "https://my-app.gptengineer.app")).toBe("lovable");
  });

  it("detects Bolt.new by hostname", () => {
    expect(detectAgentEnvironment([], "https://my-app.stackblitz.io")).toBe("bolt");
  });

  it("detects Bolt.new by tech prefix", () => {
    expect(detectAgentEnvironment(["Bolt.new"], "https://myapp.com")).toBe("bolt");
  });

  it("detects Next.js", () => {
    expect(detectAgentEnvironment(["Next.js 14", "React"], "https://myapp.com")).toBe("nextjs");
  });

  it("detects WordPress", () => {
    expect(detectAgentEnvironment(["WordPress 6.5", "PHP"], "https://blog.com")).toBe("wordpress");
  });

  it("detects Supabase without a major framework", () => {
    expect(detectAgentEnvironment(["Supabase", "React"], "https://app.com")).toBe("supabase");
  });

  it("Supabase + Next.js returns nextjs (Next.js wins)", () => {
    expect(detectAgentEnvironment(["Supabase", "Next.js 14"], "https://app.com")).toBe("nextjs");
  });

  it("Supabase + Nuxt returns nextjs-tier (Nuxt is a major framework)", () => {
    expect(detectAgentEnvironment(["Supabase", "Nuxt.js"], "https://app.com")).toBe("generic");
  });

  it("falls back to generic for unrecognised stack", () => {
    expect(detectAgentEnvironment(["React", "Tailwind CSS"], "https://myapp.com")).toBe("generic");
  });

  it("Lovable hostname takes priority over Next.js tech", () => {
    expect(detectAgentEnvironment(["Next.js 14"], "https://app.lovable.app")).toBe("lovable");
  });

  it("returns generic for empty inputs", () => {
    expect(detectAgentEnvironment([], "https://example.com")).toBe("generic");
  });

  it("returns generic for invalid URL (does not throw)", () => {
    expect(detectAgentEnvironment(["React"], "not-a-url")).toBe("generic");
  });

  it("tech matching is case-insensitive (lovable lower-cased internally)", () => {
    expect(detectAgentEnvironment(["LOVABLE"], "https://myapp.com")).toBe("lovable");
  });
});

describe("the AI analysis is grounded in the scan's own findings", () => {
  // A clean site once got "Missing Content-Security-Policy Header" in its fix
  // prompt: the prompt primed the model with common vibe-coding problems and
  // demanded exactly three priorities, so with one finding it invented two.
  type Sent = { model: string; temperature: number; messages: Array<{ content: string }> };
  async function capture(
    vulns: any[] = [],
    tests: any[] = [],
    reply: unknown = null,
  ): Promise<{ system: string; user: string; sent: Sent; result: any }> {
    const { callDeepSeek } = await import("./deepseek.js");
    const realFetch = globalThis.fetch;
    const realKey = process.env.DEEPSEEK_API_KEY;
    let sent: Sent | null = null;
    process.env.DEEPSEEK_API_KEY = "test-key";
    globalThis.fetch = (async (_u: unknown, init: { body: string }) => {
      sent = JSON.parse(init.body);
      return reply
        ? new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(reply) } }] }), { status: 200 })
        : new Response("{}", { status: 500 });
    }) as unknown as typeof fetch;
    let result: any;
    try {
      result = await callDeepSeek("https://example.com", vulns, ["Astro", "React"], "deep", tests);
    } finally {
      globalThis.fetch = realFetch;
      if (realKey === undefined) delete process.env.DEEPSEEK_API_KEY;
      else process.env.DEEPSEEK_API_KEY = realKey;
    }
    return { system: sent!.messages[0]!.content, user: sent!.messages[1]!.content, sent: sent!, result };
  }
  const capturePrompt = () => capture();

  it("forbids reporting problems the scanner did not find", async () => {
    const { system, user } = await capturePrompt();
    expect(user).toMatch(/Never say something is missing, misconfigured, exposed or vulnerable unless a finding above reports it/);
    expect(user).toMatch(/Never assume one of them is present/);
    expect(system).toMatch(/ONLY source of truth/);
    expect(system).toMatch(/Never say a header, file, key, setting or weakness is present, missing or misconfigured unless a listed finding says so/);
  });

  it("keeps severities, and bans invented numbers and compliance verdicts", async () => {
    const { system } = await capturePrompt();
    expect(system).toMatch(/Keep every severity exactly as given/);
    expect(system).toMatch(/Never invent file paths, endpoints, keys, versions, CVE numbers, statistics/);
    expect(system).toMatch(/never state or imply the site is compliant/);
  });

  it("uses DeepSeek-V4.1-Flash (deepseek-flash) at a low temperature", async () => {
    const { sent } = await capturePrompt();
    expect(sent.model).toBe("deepseek-flash");
    expect(sent.temperature).toBeLessThanOrEqual(0.1);
  });

  it("tells the model what was NOT tested, so it cannot call it safe", async () => {
    const { user, system } = await capture([], [
      { group: "active", name: "injection (XSS, SQLi)", status: "ran", findings: 0, durationMs: 5 },
      { group: "active", name: "cross-account access control (IDOR)", status: "skipped", findings: 0, durationMs: 0, reason: "needs sign-ins for two test accounts on the scan" },
    ]);
    expect(user).toContain("1 of 2 tests ran.");
    expect(user).toContain("NOT tested on this scan");
    expect(user).toContain("- cross-account access control (IDOR): needs sign-ins for two test accounts on the scan");
    expect(system).toMatch(/Never call an area safe, secure or clean if the scan did not test it/);
  });

  it("cuts priorities and quick wins the model padded beyond the real findings", async () => {
    const one = [{ id: "1", name: "DMARC Policy Set to None", severity: "medium", category: "Email", description: "d", solution: "s" }];
    const { result } = await capture(one, [], {
      overallRisk: "r",
      topPriorities: ["Fix DMARC", "Add a CSP header", "Rotate keys"],
      quickWins: ["Add HSTS", "Add X-Frame-Options"],
      complianceNotes: null,
      agentFixPrompt: "p",
    });
    expect(result.topPriorities).toEqual(["Fix DMARC"]);
    expect(result.quickWins).toEqual(["Add HSTS"]);
  });

  it("returns no priorities at all for a scan with no findings", async () => {
    const { result } = await capture([], [], {
      overallRisk: "r", topPriorities: ["Add a CSP header"], quickWins: ["Add HSTS"], complianceNotes: null, agentFixPrompt: "p",
    });
    expect(result.topPriorities).toEqual([]);
    expect(result.quickWins).toEqual([]);
  });

  it("does not demand a fixed number of priorities", async () => {
    const { user } = await capturePrompt();
    expect(user).toMatch(/never more items than findings/);
    expect(user).toMatch(/Empty array if none qualify/);
    expect(user).not.toMatch(/Third priority/);
  });

  it("does not ask the editor for code changes when no finding needs one", async () => {
    const { user } = await capturePrompt();
    expect(user).toMatch(/If none of the findings needs a code change/);
  });

  it("carries no unsourced statistics into the report", async () => {
    const { user } = await capturePrompt();
    expect(user).not.toMatch(/91\.5%/);
  });
});
