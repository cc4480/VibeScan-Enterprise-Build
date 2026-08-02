import { Router, type IRouter } from "express";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import {
  GetDeepseekKeyStatusResponse,
  SetDeepseekKeyBody,
  SetDeepseekKeyResponse,
  DeleteDeepseekKeyResponse,
} from "@workspace/api-zod";
import { encryptSecret, isEncryptionConfigured } from "../lib/crypto";

const router: IRouter = Router();

router.get("/settings/deepseek-key", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const [user] = await db
      .select({ last4: usersTable.deepseekApiKeyLast4 })
      .from(usersTable)
      .where(eq(usersTable.id, req.user.id));

    res.json(
      GetDeepseekKeyStatusResponse.parse({
        configured: Boolean(user?.last4),
        last4: user?.last4 ?? null,
      }),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to fetch DeepSeek key status");
    res.status(500).json({ error: "Failed to fetch DeepSeek key status" });
  }
});

router.put("/settings/deepseek-key", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  if (!isEncryptionConfigured()) {
    res.status(503).json({ error: "This server isn't configured to store personal API keys yet" });
    return;
  }

  const parseResult = SetDeepseekKeyBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.issues.map((i) => i.message).join(", ") });
    return;
  }

  const apiKey = parseResult.data.apiKey.trim();
  if (!apiKey.startsWith("sk-") || apiKey.length < 20) {
    res.status(400).json({
      error: 'That doesn\'t look like a valid DeepSeek API key — it should start with "sk-".',
    });
    return;
  }

  try {
    const encrypted = encryptSecret(apiKey);
    const last4 = apiKey.slice(-4);

    await db
      .update(usersTable)
      .set({ deepseekApiKeyEncrypted: encrypted, deepseekApiKeyLast4: last4 })
      .where(eq(usersTable.id, req.user.id));

    res.json(SetDeepseekKeyResponse.parse({ configured: true, last4 }));
  } catch (err) {
    req.log.error({ err }, "Failed to save DeepSeek key");
    res.status(500).json({ error: "Failed to save DeepSeek key" });
  }
});

router.delete("/settings/deepseek-key", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    await db
      .update(usersTable)
      .set({ deepseekApiKeyEncrypted: null, deepseekApiKeyLast4: null })
      .where(eq(usersTable.id, req.user.id));

    res.json(DeleteDeepseekKeyResponse.parse({ configured: false, last4: null }));
  } catch (err) {
    req.log.error({ err }, "Failed to remove DeepSeek key");
    res.status(500).json({ error: "Failed to remove DeepSeek key" });
  }
});

export default router;
