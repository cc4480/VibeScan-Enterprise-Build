/**
 * Report branding: the name an account's PDFs and shared reports carry as "prepared by".
 *
 * The name is public by design (it is printed on whatever the account shares), so it is cleaned on the way in: control
 * characters and runs of space are collapsed, it is bounded, and it is rendered only as text by the pages. A brand that
 * looks like a web address or an email is refused, so the field cannot be used to put a link or a lure on a shared report.
 */
import { eq } from "drizzle-orm";
import { db, usersTable } from "@workspace/db";

export const BRAND_MAX = 60;

/** Control characters and the zero-width and direction-changing characters that make a name look like something else. */
const invisible = (cp: number) => cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);

export interface Brand { name: string; poweredBy: boolean }

/** The cleaned name, null for "no branding", or `false` when the text is not acceptable. */
export function cleanBrandName(input: unknown): string | null | false {
  if (input === null || input === undefined) return null;
  if (typeof input !== "string") return false;
  const name = [...input].map((c) => (invisible(c.codePointAt(0)!) ? " " : c)).join("").replace(/\s+/g, " ").trim();
  if (name === "") return null;
  if (name.length > BRAND_MAX) return false;
  if (/https?:|www\.|@|[<>]|\.[a-z]{2,}(\/|$|\s)/i.test(name)) return false;
  return name;
}

export async function getBranding(userId: string): Promise<Brand | null> {
  const [row] = await db.select({ name: usersTable.brandName, poweredBy: usersTable.brandPoweredBy }).from(usersTable).where(eq(usersTable.id, userId));
  return row?.name ? { name: row.name, poweredBy: row.poweredBy } : null;
}

export async function setBranding(userId: string, name: string | null, poweredBy: boolean): Promise<void> {
  await db.update(usersTable).set({ brandName: name, brandPoweredBy: poweredBy }).where(eq(usersTable.id, userId));
}
