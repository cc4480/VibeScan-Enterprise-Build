/**
 * Teams: an account invites teammates by email, and a teammate who accepts can read that account's reports and monitored
 * sites and download evidence packs. That is the "viewer" role. An "editor" can also pause and resume the owner's monitors and
 * file tickets from the owner's reports (GitHub, Linear, Jira), through the owner's saved destinations. Nothing more, in either
 * role: they cannot scan, spend credits or the plan, change settings or saved credentials, manage the team, see billing or
 * touch anything else that is the owner's to change, and scans, billing and quota stay with the owner.
 *
 * Access is checked against this table on every read (isTeamViewer), never cached in a session, so removing a teammate ends
 * their access on their next request. An invitation is a one-time token bound to the invited address: only a signed-in
 * account with that exact address can accept it, so a forwarded or leaked link is of no use to anyone else. Only the token's
 * hash is stored.
 */
import { createHash, randomBytes } from "node:crypto";
import { and, desc, eq, sql } from "drizzle-orm";
import { db, reportsTable, teamMembersTable, usersTable } from "@workspace/db";
import { APP_ORIGIN } from "./appOrigin";

export const MAX_TEAM = 10;
/** A pending invitation can be sent again, but not more often than this: re-inviting must not become a way to spam an address. */
export const RESEND_AFTER_MS = 10 * 60_000;

export type Role = "viewer" | "editor";
export const ROLES: readonly Role[] = ["viewer", "editor"];
/** A role from a request: anything but "editor" is a viewer, the lesser of the two. */
export const roleOf = (raw: unknown): Role => (raw === "editor" ? "editor" : "viewer");

export type Failure = { ok: false; status: 400 | 403 | 404 | 409 | 429; code: string; message: string };
const fail = (status: Failure["status"], code: string, message: string): Failure => ({ ok: false, status, code, message });

export function normalizeEmail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const email = raw.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@<>()",;:\\]+@[^\s@<>()",;:\\]+\.[^\s@<>()",;:\\]{2,}$/.test(email) ? email : null;
}

export const hashInviteToken = (token: string) => createHash("sha256").update(token, "utf8").digest("hex");
const mintInviteToken = () => randomBytes(32).toString("hex");
export const inviteUrl = (token: string) => `${APP_ORIGIN}/team/accept?token=${token}`;

// ── The owner's side ──────────────────────────────────────────────────────────

export async function inviteMember(ownerId: string, ownerEmail: string | null | undefined, rawEmail: unknown, role: Role = "viewer"): Promise<{ ok: true; email: string; url: string; resent: boolean } | Failure> {
  const email = normalizeEmail(rawEmail);
  if (!email) return fail(400, "bad_email", "Enter the teammate's email address.");
  if (email === (ownerEmail ?? "").trim().toLowerCase()) return fail(400, "own_address", "That is your own address.");

  const token = mintInviteToken();
  return db.transaction(async (tx) => {
    // Two invitations for the same address at once take turns, so the team limit and the one-row-per-address rule hold.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`team:${ownerId}`}))`);
    const rows = await tx.select().from(teamMembersTable).where(eq(teamMembersTable.userId, ownerId));
    const existing = rows.find((r) => r.invitedEmail === email);
    if (existing?.status === "active") return fail(409, "already_member", "That person is already on your team.");
    if (existing) {
      if (Date.now() - existing.createdAt.getTime() < RESEND_AFTER_MS) {
        return fail(429, "resend_too_soon", "An invitation was sent to that address a moment ago. Wait a few minutes before sending it again.");
      }
      // A pending invitation is reissued: a new link, and the old one stops working.
      await tx.update(teamMembersTable).set({ tokenHash: hashInviteToken(token), createdAt: new Date(), role }).where(eq(teamMembersTable.id, existing.id));
      return { ok: true as const, email, url: inviteUrl(token), resent: true };
    }
    if (rows.length >= MAX_TEAM) return fail(409, "team_full", `A team can have up to ${MAX_TEAM} people, including pending invitations. Remove someone first.`);
    await tx.insert(teamMembersTable).values({ userId: ownerId, invitedEmail: email, tokenHash: hashInviteToken(token), role });
    return { ok: true as const, email, url: inviteUrl(token), resent: false };
  });
}

export interface TeamRow { id: string; email: string; role: Role; status: "pending" | "active"; createdAt: string; acceptedAt: string | null }

export async function listTeam(ownerId: string): Promise<TeamRow[]> {
  const rows = await db.select().from(teamMembersTable).where(eq(teamMembersTable.userId, ownerId)).orderBy(teamMembersTable.createdAt);
  return rows.map((r) => ({ id: r.id, email: r.invitedEmail, role: r.role, status: r.status, createdAt: r.createdAt.toISOString(), acceptedAt: r.acceptedAt?.toISOString() ?? null }));
}

/** Changes what a teammate (or a pending invitation) may do; only the owner's own rows. False when there is no such row. */
export async function setRole(ownerId: string, id: string, role: Role): Promise<boolean> {
  const done = await db.update(teamMembersTable).set({ role }).where(and(eq(teamMembersTable.id, id), eq(teamMembersTable.userId, ownerId))).returning({ id: teamMembersTable.id });
  return done.length > 0;
}

/** Removes a pending invitation or an active teammate; their access ends with their next request. */
export async function removeMember(ownerId: string, id: string): Promise<boolean> {
  const gone = await db.delete(teamMembersTable).where(and(eq(teamMembersTable.id, id), eq(teamMembersTable.userId, ownerId))).returning({ id: teamMembersTable.id });
  return gone.length > 0;
}

// ── The teammate's side ───────────────────────────────────────────────────────

export async function acceptInvite(userId: string, userEmail: string | null | undefined, token: unknown): Promise<{ ok: true } | Failure> {
  const invalid = fail(404, "invalid_invite", "This invitation is not valid. It may have been used already, replaced by a newer one, or withdrawn.");
  if (typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) return invalid;
  const [row] = await db.select().from(teamMembersTable).where(and(eq(teamMembersTable.tokenHash, hashInviteToken(token)), eq(teamMembersTable.status, "pending")));
  if (!row) return invalid;
  if (row.userId === userId) return fail(400, "own_team", "You cannot join your own team.");
  if ((userEmail ?? "").trim().toLowerCase() !== row.invitedEmail) {
    return fail(403, "wrong_account", "This invitation was sent to a different email address. Sign in with the address it was sent to.");
  }
  // The pending condition is in the update, so two people redeeming one link cannot both succeed.
  const done = await db.update(teamMembersTable)
    .set({ memberId: userId, status: "active", tokenHash: null, acceptedAt: new Date() })
    .where(and(eq(teamMembersTable.id, row.id), eq(teamMembersTable.status, "pending")))
    .returning({ id: teamMembersTable.id });
  return done.length > 0 ? { ok: true } : invalid;
}

/** A team the caller is on. `id` is the membership, not the owner: the owner's account id is never handed to a teammate. */
export interface SharedWithMe { id: string; ownerEmail: string | null; since: string | null; role: Role }

export async function sharedWithMe(memberId: string): Promise<SharedWithMe[]> {
  const rows = await db.select({ id: teamMembersTable.id, since: teamMembersTable.acceptedAt, ownerEmail: usersTable.email, role: teamMembersTable.role })
    .from(teamMembersTable).leftJoin(usersTable, eq(usersTable.id, teamMembersTable.userId))
    .where(and(eq(teamMembersTable.memberId, memberId), eq(teamMembersTable.status, "active"))).orderBy(teamMembersTable.acceptedAt);
  return rows.map((r) => ({ id: r.id, ownerEmail: r.ownerEmail ?? null, since: r.since?.toISOString() ?? null, role: r.role }));
}

/** A teammate leaves a team: only their own membership, and only an active one. */
export async function leaveTeam(memberId: string, id: string): Promise<boolean> {
  const gone = await db.delete(teamMembersTable).where(and(eq(teamMembersTable.id, id), eq(teamMembersTable.memberId, memberId))).returning({ id: teamMembersTable.id });
  return gone.length > 0;
}

/** May `viewerId` read `ownerId`'s reports? Asked on every read. */
export async function isTeamViewer(viewerId: string, ownerId: string): Promise<boolean> {
  if (viewerId === ownerId) return false; // an owner is not a viewer of their own reports; callers check ownership first
  const [row] = await db.select({ id: teamMembersTable.id }).from(teamMembersTable)
    .where(and(eq(teamMembersTable.userId, ownerId), eq(teamMembersTable.memberId, viewerId), eq(teamMembersTable.status, "active"))).limit(1);
  return Boolean(row);
}

/** What `viewerId` is on `ownerId`'s team: null when not on it. Asked on every request that depends on it. */
export async function teamRoleOf(viewerId: string, ownerId: string): Promise<Role | null> {
  if (viewerId === ownerId) return null;
  const [row] = await db.select({ role: teamMembersTable.role }).from(teamMembersTable)
    .where(and(eq(teamMembersTable.userId, ownerId), eq(teamMembersTable.memberId, viewerId), eq(teamMembersTable.status, "active"))).limit(1);
  return row?.role ?? null;
}

/** May `actorId` act on `ownerId`'s monitors and filing? The owner, or an active editor on their team. */
export async function mayActFor(actorId: string, ownerId: string): Promise<boolean> {
  return actorId === ownerId || (await teamRoleOf(actorId, ownerId)) === "editor";
}

/**
 * Whose account an action on this report runs as: the caller's own when it is their report, the owner's when the caller is an
 * active editor on the owner's team, and null otherwise (including a viewer, and a report that does not exist).
 */
export async function actingOwnerForReport(actorId: string, reportId: string): Promise<string | null> {
  const [report] = await db.select({ userId: reportsTable.userId }).from(reportsTable).where(eq(reportsTable.id, reportId));
  if (!report) return null;
  return (await mayActFor(actorId, report.userId)) ? report.userId : null;
}

export interface SharedReportRow { id: string; targetUrl: string; scannedAt: string; tier: string; grade: string | null }

/** The newest reports of the team with this membership id, for the teammate; null when the caller is not on that team. */
export async function sharedReports(viewerId: string, membershipId: string, limit = 50): Promise<SharedReportRow[] | null> {
  const [m] = await db.select({ ownerId: teamMembersTable.userId }).from(teamMembersTable)
    .where(and(eq(teamMembersTable.id, membershipId), eq(teamMembersTable.memberId, viewerId), eq(teamMembersTable.status, "active"))).limit(1);
  if (!m) return null;
  const ownerId = m.ownerId;
  const rows = await db.select({ id: reportsTable.id, targetUrl: reportsTable.targetUrl, scannedAt: reportsTable.scannedAt, tier: reportsTable.tier, data: reportsTable.data })
    .from(reportsTable).where(eq(reportsTable.userId, ownerId)).orderBy(desc(reportsTable.scannedAt)).limit(Math.min(Math.max(limit, 1), 100));
  return rows.map((r) => {
    const grade = (r.data as { summary?: { grade?: unknown } } | null)?.summary?.grade;
    return { id: r.id, targetUrl: r.targetUrl, scannedAt: r.scannedAt.toISOString(), tier: r.tier, grade: typeof grade === "string" ? grade : null };
  });
}
