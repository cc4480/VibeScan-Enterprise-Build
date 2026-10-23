/**
 * Create, list and revoke personal API tokens (Settings → AI editors).
 *
 * Session-authenticated only. The global auth middleware never accepts an
 * "ssk_" token, so a token cannot be used to mint more tokens or to revoke the
 * ones that would lock an attacker out.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { db, apiTokensTable } from "@workspace/db";
import { and, desc, eq, isNull } from "drizzle-orm";
import { generateToken, liveTokenCount, MAX_TOKENS_PER_USER, TOKEN_SCOPES } from "../lib/apiTokens";

const router: IRouter = Router();

const CreateBody = z.object({
  name: z.string().trim().min(1).max(60),
  // Omitted means "mcp": what this endpoint issued before there was an API.
  scope: z.enum(TOKEN_SCOPES as [string, ...string[]]).default("mcp"),
});

router.get("/account/tokens", async (req, res): Promise<void> => {
  if (!req.isAuthenticated() || !req.user.email) {
    res.status(401).json({ error: "Sign in to manage API tokens." });
    return;
  }
  const rows = await db
    .select({
      id: apiTokensTable.id,
      name: apiTokensTable.name,
      prefix: apiTokensTable.prefix,
      scope: apiTokensTable.scope,
      createdAt: apiTokensTable.createdAt,
      lastUsedAt: apiTokensTable.lastUsedAt,
    })
    .from(apiTokensTable)
    // Apps connected by OAuth appear under "Connected apps", not here.
    .where(and(eq(apiTokensTable.userId, req.user.id), isNull(apiTokensTable.revokedAt), isNull(apiTokensTable.oauthClientId)))
    .orderBy(desc(apiTokensTable.createdAt));
  res.json({ tokens: rows, max: MAX_TOKENS_PER_USER });
});

router.post("/account/tokens", async (req, res): Promise<void> => {
  // A registered account, not a legacy browser-only identity: a token is a
  // standing credential, and it has to belong to someone who can revoke it.
  if (!req.isAuthenticated() || !req.user.email) {
    res.status(401).json({ error: "Sign in to create an API token." });
    return;
  }
  const parsed = CreateBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Give the token a name, up to 60 characters." });
    return;
  }
  if ((await liveTokenCount(req.user.id)) >= MAX_TOKENS_PER_USER) {
    res.status(409).json({ error: `You can have ${MAX_TOKENS_PER_USER} tokens. Revoke one you no longer use first.` });
    return;
  }

  const { token, hash, prefix } = generateToken();
  const [row] = await db
    .insert(apiTokensTable)
    .values({ userId: req.user.id, name: parsed.data.name, tokenHash: hash, prefix, scope: parsed.data.scope as "mcp" | "api" })
    .returning({ id: apiTokensTable.id, name: apiTokensTable.name, prefix: apiTokensTable.prefix, scope: apiTokensTable.scope, createdAt: apiTokensTable.createdAt });

  req.log.info({ tokenId: row!.id }, "API token created");
  // The only time the token itself is ever returned.
  res.status(201).json({ ...row, token });
});

router.delete("/account/tokens/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated() || !req.user.email) {
    res.status(401).json({ error: "Sign in to manage API tokens." });
    return;
  }
  // Not a UUID: Postgres would reject the comparison with a 500. It names no
  // token, so it gets the same 404 as any other id that is not yours.
  if (!/^[0-9a-f-]{36}$/i.test(req.params.id)) {
    res.status(404).json({ error: "Token not found." });
    return;
  }
  // Scoped to the owner: another user's token id revokes nothing and reveals
  // nothing — the same 404 as an id that never existed.
  const revoked = await db
    .update(apiTokensTable)
    .set({ revokedAt: new Date() })
    .where(and(eq(apiTokensTable.id, req.params.id), eq(apiTokensTable.userId, req.user.id), isNull(apiTokensTable.revokedAt)))
    .returning({ id: apiTokensTable.id });
  if (revoked.length === 0) {
    res.status(404).json({ error: "Token not found." });
    return;
  }
  req.log.info({ tokenId: req.params.id }, "API token revoked");
  res.status(204).end();
});

export default router;
