import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildServerCard } from "./serverCard";

// The committed card is what directories like Smithery read. If a tool is
// added, renamed or re-described in routes/mcp.ts and the card is not rebuilt,
// directories advertise tools that do not exist (or miss ones that do).
const committed = JSON.parse(
  readFileSync(resolve(__dirname, "../../../vibescan/public/.well-known/mcp/server-card.json"), "utf8"),
);

describe("the public MCP server card", () => {
  it("matches the live tool definitions — rebuild with scripts/build-server-card.ts if this fails", async () => {
    const live = await buildServerCard();
    expect(committed.serverInfo).toEqual(live.serverInfo);
    expect(committed.tools).toEqual(live.tools);
    expect(committed.instructions).toEqual(live.instructions);
  });

  it("says a token is required and where to get one", () => {
    expect(committed.authentication).toMatchObject({ required: true, schemes: ["bearer"], header: "Authorization" });
    expect(committed.authentication.obtain).toBe("https://secscan.us/settings#ai-editors");
    expect(committed.endpoint).toBe("https://secscan.us/api/mcp");
  });
});
