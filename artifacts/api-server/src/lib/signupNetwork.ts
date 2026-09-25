/**
 * New accounts per network.
 *
 * Every account gets free scans every month, so an account is worth something
 * to create. Without a cap one network can mint as many as it has addresses to
 * type. The cap is on the NETWORK: an IPv4 address, or the /64 of an IPv6 one —
 * a single household or phone is handed a whole /64, so keying on the full IPv6
 * address would let anyone rotate past the cap for free.
 *
 * The address itself is never stored. networkKey() is a keyed hash, compared
 * only for equality, so the column cannot be turned back into an IP.
 *
 * Both ways of creating an account check this: email sign-up (at step one,
 * before the code is sent, and again when it is redeemed) and Google sign-in
 * (only when it would create a new account, never for an existing one).
 */
import { createHmac } from "node:crypto";
import { isIPv4, isIPv6 } from "node:net";
import { db, usersTable } from "@workspace/db";
import { and, count, eq, gt } from "drizzle-orm";

const DAY_MS = 24 * 60 * 60 * 1000;

function positiveInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

/** New accounts one network may create per window. */
export const ACCOUNTS_PER_NETWORK = positiveInt(process.env["SIGNUP_LIMIT_PER_NETWORK"], 2);
/** The window, in days. Matches the monthly free-scan cycle. */
export const SIGNUP_WINDOW_DAYS = positiveInt(process.env["SIGNUP_LIMIT_WINDOW_DAYS"], 30);

export const NETWORK_LIMIT_MESSAGE =
  `This network has already created ${ACCOUNTS_PER_NETWORK} accounts in the last ${SIGNUP_WINDOW_DAYS} days, ` +
  "which is the limit. Sign in to an existing account instead, or contact hello@secscan.us if you need another.";

/** Expand an IPv6 address to its eight hextets, lowercase, no zero compression. */
function expandIPv6(ip: string): string[] | null {
  const [head, tail, extra] = ip.toLowerCase().split("::");
  if (extra !== undefined) return null;
  const left = head ? head.split(":") : [];
  const right = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const missing = 8 - left.length - right.length;
  if (tail === undefined ? left.length !== 8 : missing < 0) return null;
  return [...left, ...Array(tail === undefined ? 0 : missing).fill("0"), ...right].map((h) => h.padStart(4, "0"));
}

/**
 * The network an address belongs to: the IPv4 address itself, or the first
 * four hextets (/64) of an IPv6 one. IPv4-mapped IPv6 (::ffff:1.2.3.4) is
 * treated as the IPv4 it carries. Exported for tests.
 */
export function networkOf(ip: string): string {
  const addr = ip.trim().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (mapped) return mapped[1]!;
  if (isIPv4(addr)) return addr;
  if (isIPv6(addr)) {
    const hextets = expandIPv6(addr);
    if (hextets) return `${hextets.slice(0, 4).join(":")}::/64`;
  }
  // Unparseable: still bucket it, rather than letting an odd value dodge the cap.
  return `raw:${addr}`;
}

function hmacKey(): string {
  const key = process.env["ENCRYPTION_KEY"];
  if (key) return key;
  if (process.env["NODE_ENV"] === "production") {
    throw new Error("ENCRYPTION_KEY is required to key the signup-network hash");
  }
  return "dev-only-signup-network-key";
}

/** The stored, non-reversible form of a network. Exported for tests. */
export function networkKey(ip: string): string {
  return createHmac("sha256", hmacKey()).update(`signup-network:${networkOf(ip)}`).digest("hex");
}

/** Accounts created from this network inside the window. */
export async function recentSignups(network: string, now: Date = new Date()): Promise<number> {
  const since = new Date(now.getTime() - SIGNUP_WINDOW_DAYS * DAY_MS);
  const [row] = await db
    .select({ n: count() })
    .from(usersTable)
    .where(and(eq(usersTable.signupNetwork, network), gt(usersTable.createdAt, since)));
  return Number(row?.n ?? 0);
}

/** True when this network may create another account now. */
export async function networkMaySignUp(network: string, now: Date = new Date()): Promise<boolean> {
  return (await recentSignups(network, now)) < ACCOUNTS_PER_NETWORK;
}
