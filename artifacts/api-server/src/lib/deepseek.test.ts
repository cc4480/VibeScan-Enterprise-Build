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
