/**
 * Writes the public MCP server card from the live tool definitions:
 *
 *   APP_ORIGIN=https://secscan.us DATABASE_URL=postgres://localhost/x \
 *     npx tsx artifacts/api-server/scripts/build-server-card.ts
 *
 * Re-run after changing any tool in routes/mcp.ts; serverCard.test.ts fails
 * until the committed card matches. DATABASE_URL is only needed because
 * lib/db reads it on import — nothing connects.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildServerCard } from "../src/lib/serverCard";

const out = resolve(dirname(fileURLToPath(import.meta.url)), "../../vibescan/public/.well-known/mcp/server-card.json");
const card = await buildServerCard();
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(card, null, 2) + "\n");
console.log(`Wrote ${out}: ${(card.tools as unknown[]).length} tools`);
process.exit(0);
