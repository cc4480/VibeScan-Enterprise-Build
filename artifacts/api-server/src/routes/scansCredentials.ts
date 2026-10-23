/** The stored logins for an authenticated scan: who may keep them, whether they are usable, and the encryption. */
import { type Request } from "express";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { validateCredentials, encryptCredentials, sameAccountInput, type ScanCredentialInput } from "../lib/scanCredentials";

export type PreparedCredentials =
  | {
      ok: true;
      credentialsEncrypted: string | null;
      secondaryCredentialsEncrypted: string | null;
      credentialsAuthorizedAt: Date | null;
    }
  | { ok: false; status: number; error: string };

/**
 * Check and encrypt the logins sent with a scan request. On a refusal the caller gives back whatever the
 * request charged and answers with the status and message returned here.
 */
export async function prepareScanCredentials(
  userId: string,
  credentials: ScanCredentialInput | null | undefined,
  secondaryCredentials: ScanCredentialInput | null | undefined,
  log: Request["log"],
): Promise<PreparedCredentials> {
  // ── Credentials for an authenticated scan ──────────────────────────────────
  // Validated before the scan is queued so a bad login is reported now rather
  // than as a mysteriously empty report later. Encrypted immediately; the
  // plaintext never reaches the database or the job payload.
  let credentialsEncrypted: string | null = null;
  let secondaryCredentialsEncrypted: string | null = null;
  let credentialsAuthorizedAt: Date | null = null;

  if (credentials) {
    // A credentialed scan means holding a customer's live login. An anonymous
    // identity is a UUID in localStorage, auto-accepted on sight — no password,
    // no second factor, nothing to revoke — so anyone who copies that string
    // becomes the user and inherits the stored credential. Storing a production
    // password against that is not a risk worth taking for the convenience of
    // skipping registration, so credentials require a real, verified account.
    // Anonymous users keep full access to unauthenticated scanning.
    const [account] = await db
      .select({
        passwordHash: usersTable.passwordHash,
        emailVerifiedAt: usersTable.emailVerifiedAt,
      })
      .from(usersTable)
      .where(eq(usersTable.id, userId))
      .limit(1);

    if (!account?.passwordHash) {
      return {
        ok: false,
        status: 403,
        error:
          "Authenticated scanning needs a registered account. Create one to " +
          "store login details for a scan — your existing scans stay with you.",
      };
    }

    if (!account.emailVerifiedAt) {
      return {
        ok: false,
        status: 403,
        error: "Verify your email address before storing login details for a scan.",
      };
    }

    const check = validateCredentials(credentials);
    if (!check.ok) {
      return { ok: false, status: 400, error: check.error ?? "" };
    }
    credentialsEncrypted = encryptCredentials(credentials);
    credentialsAuthorizedAt = new Date();
    // Logged without the credentials themselves — see the redaction list in
    // lib/logger.ts.
    log.info({ mode: credentials.mode }, "Credentialed scan requested");

    // A second account unlocks access-control testing. It is only meaningful
    // alongside the first — comparing one account against nothing proves
    // nothing about authorisation between users.
    if (secondaryCredentials) {
      const secondCheck = validateCredentials(secondaryCredentials);
      if (!secondCheck.ok) {
        return { ok: false, status: 400, error: `Second account: ${secondCheck.error}` };
      }
      if (sameAccountInput(credentials, secondaryCredentials)) {
        return {
          ok: false,
          status: 400,
          error:
            "Second account: this is the same account as the first. Two sign-ins for one user would " +
            "always see the same records, so the comparison could prove nothing. Supply a different account.",
        };
      }
      secondaryCredentialsEncrypted = encryptCredentials(secondaryCredentials);
      log.info("Access-control testing enabled — second account supplied");
    }
  } else if (secondaryCredentials) {
    return {
      ok: false,
      status: 400,
      error: "A second account only works alongside a first one. Add primary credentials too.",
    };
  }

  return { ok: true, credentialsEncrypted, secondaryCredentialsEncrypted, credentialsAuthorizedAt };
}
