import { describe, it, expect } from "vitest";
import { checkSupabaseRLS } from "./probesSupabase";

describe("checkSupabaseRLS on a page with no Supabase", () => {
  it("says it had nothing to test instead of passing silently", async () => {
    let reason: string | undefined;
    const found = await checkSupabaseRLS("<html><body>plain site</body></html>", (r) => { reason = r; });
    expect(found).toEqual([]);
    expect(reason).toMatch(/No Supabase project/);
  });
});
