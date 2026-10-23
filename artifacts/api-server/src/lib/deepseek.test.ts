import { describe, it, expect, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";

// The AI provider is a real local server: LLM_ENDPOINT (the operator setting that points the call at any
// OpenAI-compatible provider) is aimed at it before the module loads. A test sets what it answers and reads what the
// call sent.
const provider = { reply: null as unknown, sentBody: null as string | null };
const sockets = new Set<Socket>();
const providerServer = http.createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    provider.sentBody = Buffer.concat(chunks).toString("utf8");
    if (provider.reply) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(provider.reply) } }] }));
    } else {
      res.writeHead(500).end("{}");
    }
  });
});
providerServer.on("connection", (sock) => { sockets.add(sock); sock.on("close", () => sockets.delete(sock)); });
await new Promise<void>((r) => providerServer.listen(0, "127.0.0.1", r));
process.env["LLM_ENDPOINT"] = `http://127.0.0.1:${(providerServer.address() as AddressInfo).port}/v1/chat/completions`;
afterAll(() => new Promise<void>((r) => { for (const sock of sockets) sock.destroy(); providerServer.close(() => r()); }));

// Imported only now: the endpoint is read when the module loads.
const { detectAgentEnvironment, redactForLlm, callDeepSeek } = await import("./deepseek.js");

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

  it.each([["Shopify"], ["Wix"], ["Squarespace"], ["Webflow"]])("detects the hosted builder %s", (t) => {
    expect(detectAgentEnvironment([t, "Google Analytics"], "https://shop.example.com")).toBe("hosted");
  });

  it("detects Vercel, Netlify and Firebase when no framework is present", () => {
    expect(detectAgentEnvironment(["Vercel"], "https://a.example.com")).toBe("vercel");
    expect(detectAgentEnvironment(["Netlify"], "https://a.example.com")).toBe("netlify");
    expect(detectAgentEnvironment(["Firebase", "React"], "https://a.example.com")).toBe("firebase");
  });

  it("a framework wins over its host: Next.js on Vercel is still nextjs, Astro on Netlify is not netlify", () => {
    expect(detectAgentEnvironment(["Next.js 14", "Vercel"], "https://a.example.com")).toBe("nextjs");
    expect(detectAgentEnvironment(["Astro", "Netlify"], "https://a.example.com")).toBe("generic");
  });

  it("writes one tool-neutral prompt for every environment: same rules, only the stack notes differ", async () => {
    const { agentPromptInstructions } = await import("./deepseek-prompts.js");
    const envs = ["lovable", "nextjs", "bolt", "wordpress", "supabase", "vercel", "netlify", "firebase", "hosted", "generic"] as const;
    const rules = (e: (typeof envs)[number]) => agentPromptInstructions(e, "x.com").split("STACK NOTES")[0];
    for (const e of envs) {
      expect(rules(e)).toBe(rules("generic"));
      const text = agentPromptInstructions(e, "x.com");
      expect(text).toContain("Tool-neutral");
      expect(text).toContain("Claude Code, Cursor, Codex");
      for (const tool of ["AGENT TARGET", "@workspace", "/edit", "Composer"]) expect(text).not.toContain(tool);
    }
  });

  it("gives every host environment its own stack notes, and the hosted one never invites editing server files", async () => {
    const { agentPromptInstructions } = await import("./deepseek-prompts.js");
    for (const e of ["vercel", "netlify", "firebase", "hosted"] as const) expect(agentPromptInstructions(e, "x.com")).toContain("STACK NOTES");
    expect(agentPromptInstructions("hosted", "x.com")).toContain("Never suggest editing server files");
    expect(agentPromptInstructions("firebase", "x.com")).toContain("designed to be public");
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
    const realKey = process.env.DEEPSEEK_API_KEY;
    process.env.DEEPSEEK_API_KEY = "test-key";
    provider.reply = reply;
    provider.sentBody = null;
    let result: any;
    try {
      result = await callDeepSeek("https://example.com", vulns, ["Astro", "React"], "deep", tests);
    } finally {
      if (realKey === undefined) delete process.env.DEEPSEEK_API_KEY;
      else process.env.DEEPSEEK_API_KEY = realKey;
    }
    const sent: Sent = JSON.parse(provider.sentBody!);
    return { system: sent.messages[0]!.content, user: sent.messages[1]!.content, sent, result };
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

  it("lists findings most severe first, and keeps INFO last and conditional", async () => {
    // On seclayer.app an INFO item ("COEP — only if you use SharedArrayBuffer")
    // came back as priority #2, and the fix prompt dropped the "only if".
    const { user, system } = await capture([
      { id: "1", name: "Missing COEP", severity: "info", category: "h", description: "d", solution: "s" },
      { id: "2", name: "DMARC none", severity: "medium", category: "e", description: "d", solution: "s" },
    ]);
    expect(user.indexOf("Finding 1: DMARC none")).toBeGreaterThan(-1);
    expect(user.indexOf("Finding 2: Missing COEP")).toBeGreaterThan(user.indexOf("Finding 1: DMARC none"));
    expect(system).toMatch(/never make one a top priority or quick win while any CRITICAL, HIGH, MEDIUM or LOW finding exists/);
    expect(system).toMatch(/keep any condition they carry/);
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

describe("nothing shaped like a credential is sent to the language model", () => {
  const cases: Array<[string, string]> = [
    ["a JWT", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk1234"],
    ["a Stripe live key", "found sk_live_51H8abcdefghijkl in main.js"],
    ["an OpenAI-style key", "OPENAI=sk-proj-abcdefghijklmnop1234"],
    ["an AWS access key", "AKIAIOSFODNN7EXAMPLE"],
    ["a GitHub token", "ghp_abcdefghijklmnopqrstuvwx1234"],
    ["a Google API key", "AIzaSyA-abcdefghijklmnopqrstuvwxyz12345"],
    ["a database password in a URL", "postgres://admin:hunter2secret@db.example.com/app"],
    ["a bearer token", "Authorization: Bearer abcdef1234567890xyz"],
    ["a password assignment", 'password: "correcthorse9"'],
    ["a long opaque value", "value=" + "a1B2c3D4".repeat(6)],
  ];
  for (const [name, input] of cases) {
    it("redacts " + name, () => {
      const out = redactForLlm(input);
      expect(out).toContain("<redacted");
      expect(out).not.toMatch(/hunter2secret|correcthorse9|AKIAIOSFODNN7EXAMPLE|sk_live_51H8|ghp_abc|abcdef1234567890xyz/);
    });
  }
  it("leaves ordinary evidence alone", () => {
    const plain = "GET https://example.com/ -> 200; Header X-Frame-Options missing";
    expect(redactForLlm(plain)).toBe(plain);
  });
});
