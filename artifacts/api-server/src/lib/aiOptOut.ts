/** Has this user asked that their findings not be sent to the language-model provider? */
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";

export async function isAiAnalysisOptedOut(userId: string): Promise<boolean> {
  const [row] = await db.select({ off: usersTable.aiAnalysisOptedOut }).from(usersTable).where(eq(usersTable.id, userId));
  return row?.off === true;
}

/** The report's own note that the analysis is missing because of the owner's choice, not a failure. */
export const AI_OPT_OUT_NOTE = {
  name: "Written analysis is turned off in your settings",
  description:
    "Every security check ran and the findings below are complete. The plain-English summary, prioritised fixes and fix prompts are not generated because " +
    "you turned off AI analysis in Settings, so none of this scan's findings were sent to an AI provider. You can turn it back on at any time.",
  evidence: "Settings, Privacy: AI analysis is off for this account.",
  solution: "Nothing to fix. Turn AI analysis back on in Settings if you want the written summary and fix prompts on future scans.",
} as const;
