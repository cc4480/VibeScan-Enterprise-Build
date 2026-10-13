import { describe, it, expect } from "vitest";
import { z } from "zod";
import { zodMessage } from "./zodMessage";

describe("zodMessage", () => {
  it("names the field and gives plain text, not a JSON dump", () => {
    const r = z.object({ targetUrl: z.string(), credentials: z.object({ mode: z.enum(["form"]) }).optional() }).safeParse({ credentials: { mode: "x" } });
    expect(r.success).toBe(false);
    if (r.success) return;
    const msg = zodMessage(r.error);
    expect(msg).toContain("targetUrl:");
    expect(msg).toContain("credentials.mode:");
    expect(msg.startsWith("[")).toBe(false);
  });
});
