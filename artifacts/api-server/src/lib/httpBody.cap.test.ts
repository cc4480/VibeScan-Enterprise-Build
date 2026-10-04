import { describe, it, expect } from "vitest";
import { readBodyMarked } from "./httpBody";

describe("readBodyMarked size cap", () => {
  it("stops at the cap and marks the body truncated", async () => {
    const chunk = new Uint8Array(1024).fill(65);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        sent += chunk.length;
        c.enqueue(chunk);
      },
    });
    const { body, truncated } = await readBodyMarked(new Response(stream), 4096);
    expect(truncated).toBe(true);
    expect(body.length).toBe(4096);
    expect(sent).toBeLessThan(1024 * 100);
  });

  it("returns a small body whole", async () => {
    const { body, truncated } = await readBodyMarked(new Response("hello"), 4096);
    expect(body).toBe("hello");
    expect(truncated).toBe(false);
  });
});
