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
  async function capturePrompt(): Promise<{ system: string; user: string }> {
    const { callDeepSeek } = await import("./deepseek.js");
    const realFetch = globalThis.fetch;
    const realKey = process.env.DEEPSEEK_API_KEY;
    let body: { messages: Array<{ content: string }> } | null = null;
    process.env.DEEPSEEK_API_KEY = "test-key";
    globalThis.fetch = (async (_u: unknown, init: { body: string }) => {
      body = JSON.parse(init.body);
      return new Response("{}", { status: 500 });
    }) as unknown as typeof fetch;
    try {
      await callDeepSeek("https://example.com", [], ["Astro", "React"], "deep");
    } finally {
      globalThis.fetch = realFetch;
      if (realKey === undefined) delete process.env.DEEPSEEK_API_KEY;
      else process.env.DEEPSEEK_API_KEY = realKey;
    }
    return { system: body!.messages[0]!.content, user: body!.messages[1]!.content };
  }

  it("forbids reporting problems the scanner did not find", async () => {
    const { system, user } = await capturePrompt();
    expect(user).toMatch(/Never say something is missing, misconfigured, exposed or vulnerable unless a finding above reports it/);
    expect(user).toMatch(/Never assume one of them is present/);
    expect(system).toMatch(/report only what this scan found/);
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
