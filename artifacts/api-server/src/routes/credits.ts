import { Router, type IRouter } from "express";
import { db, creditsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { GetCreditsResponse } from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/credits", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const [credit] = await db
    .select()
    .from(creditsTable)
    .where(eq(creditsTable.userId, req.user.id));

  res.json(GetCreditsResponse.parse({ balance: credit?.balance ?? 0 }));
});

export default router;
