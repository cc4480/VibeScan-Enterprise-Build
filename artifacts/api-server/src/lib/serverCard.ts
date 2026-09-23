/**
 * The public MCP server card, served at /.well-known/mcp/server-card.json.
 *
 * Directories such as Smithery read a server's tools by connecting to it. The
 * SecScan endpoint answers an unauthenticated connect with 401 (every tool
 * needs a token), so they cannot; the card tells them what is there instead.
 *
 * Built from the live tool definitions in routes/mcp.ts through an in-memory
 * MCP client, never written by hand: the card and the server cannot describe
 * different tools. serverCard.test.ts checks the committed file against it.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Request } from "express";
import { buildServer } from "../routes/mcp";
import { APP_ORIGIN } from "./appOrigin";

export async function buildServerCard(): Promise<Record<string, unknown>> {
  // Listing tools reads only their definitions; no tool runs, so the request
  // and user are never touched.
  const server = buildServer({} as Request, { id: "server-card", email: null } as never);
  const client = new Client({ name: "server-card", version: "1" });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  const info = client.getServerVersion();
  const { tools } = await client.listTools();
  const instructions = client.getInstructions();
  await client.close();
  await server.close();

  return {
    serverInfo: { name: info?.name ?? "secscan", title: "SecScan", version: info?.version },
    description: "Scan, monitor and fix a live web app from your editor: graded security reports with fix prompts.",
    homepage: "https://secscan.info/ai-editors",
    endpoint: `${APP_ORIGIN}/api/mcp`,
    transport: "streamable-http",
    authentication: {
      required: true,
      schemes: ["bearer"],
      header: "Authorization",
      format: "Bearer <token>",
      obtain: `${APP_ORIGIN}/settings#ai-editors`,
    },
    instructions,
    tools: tools.map((t) => ({
      name: t.name,
      ...(t.title ? { title: t.title } : {}),
      description: t.description,
      inputSchema: t.inputSchema,
      ...(t.annotations ? { annotations: t.annotations } : {}),
    })),
    resources: [],
    prompts: [],
  };
}
