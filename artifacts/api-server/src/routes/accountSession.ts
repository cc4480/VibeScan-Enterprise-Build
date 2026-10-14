import { type IRouter } from "express";
import { LoginBody, isRateLimited, isLockedOut, recordFailure, maskEmail, publicUser, startSession } from "./accountShared";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { hashPassword, verifyPassword, needsRehash, dummyHash } from "../lib/password";
import { clearSession, getSessionId } from "../lib/auth";
import { LOGIN_CODE_TTL_MS, normalizeLoginCode } from "../lib/loginCode";
import { abandonLoginChallenges, issueLoginChallenge, redeemLoginChallenge } from "../lib/pendingLogin";
import { sendLoginCode } from "../lib/mailer";
import { clientIp } from "../lib/clientIp";

/** Sign-in with an emailed code, and sign-out. Deleting the account is in accountDelete.ts. */



export function registerAccountSession(router: IRouter): void {
  router.post("/account/login", async (req, res): Promise<void> => {
    if (isRateLimited(`login:${clientIp(req)}`)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }

    const parsed = LoginBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join(", ") });
      return;
    }
    const { email, password } = parsed.data;

    // One message for every failure below — a distinct "no such account" reply
    // would turn this endpoint into a way to test whether an address is
    // registered.
    const acct = `login-acct:${email}`;
    const reject = () => {
      recordFailure(acct);
      res.status(401).json({ error: "Email or password is incorrect" });
    };

    // Per account, on top of per address: guesses spread over many addresses still reach one account.
    if (isLockedOut(acct)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }

    try {
      const [row] = await db.select().from(usersTable).where(eq(usersTable.email, email));
      if (!row?.passwordHash) {
        // Spend the same hashing time as a real check, or the reply time says whether the account exists.
        await verifyPassword(password, await dummyHash());
        reject();
        return;
      }

      if (!(await verifyPassword(password, row.passwordHash))) {
        reject();
        return;
      }

      // Upgrade a hash written under weaker parameters, now that the password is
      // in hand and known correct.
      if (needsRehash(row.passwordHash)) {
        const upgraded = await hashPassword(password);
        await db.update(usersTable).set({ passwordHash: upgraded }).where(eq(usersTable.id, row.id));
      }

      // An account with no address on file cannot receive a code. That should be
      // impossible — registering requires an email — but signing someone in
      // without the second factor because their data is odd is exactly the
      // fallback an attacker would look for, so it refuses instead.
      if (!row.email) {
        req.log.error({ userId: row.id }, "Account has a password but no email — cannot send a sign-in code");
        res.status(500).json({ error: "Could not sign you in" });
        return;
      }

      const { challenge, code } = await issueLoginChallenge(row.id);

      // Deliberately awaited and NOT caught-and-ignored. sendLoginCode throws
      // where the other senders swallow, because here the mail IS the sign-in:
      // reporting success and sending nothing would leave the user at a code
      // prompt they can never satisfy.
      try {
        await sendLoginCode(row.email, code, Math.round(LOGIN_CODE_TTL_MS / 60000));
      } catch (err) {
        // Spend the challenge we just minted. Leaving it live would put a code
        // nobody received into the one-live-challenge slot, so the user's next
        // attempt would silently retire it anyway — but this keeps the table
        // honest about what is outstanding.
        await abandonLoginChallenges(row.id);
        req.log.error({ err }, "Could not send sign-in code");
        res.status(502).json({ error: "Could not send your sign-in code. Please try again shortly." });
        return;
      }

      res.json({
        twoFactorRequired: true,
        challenge,
        // Echoed so the client can show WHERE the code went without having to
        // remember the address the user typed. Masked: this response is the reply
        // to a password, and a full address here would let someone who guessed a
        // password harvest it.
        sentTo: maskEmail(row.email),
      });
    } catch (err) {
      req.log.error({ err }, "Login failed");
      res.status(500).json({ error: "Could not sign you in" });
    }
  });

  // ── Log in (step 2 of 2: emailed code) ───────────────────────────────────────

  router.post("/account/login/verify", async (req, res): Promise<void> => {
    // Keyed on IP as well as capped per challenge. The five-attempt cap is the
    // real defence; this stops a script burning someone else's five as fast as
    // the network allows.
    if (isRateLimited(`login2fa:${clientIp(req)}`)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }

    const challenge = typeof req.body?.challenge === "string" ? req.body.challenge : "";
    const code = normalizeLoginCode(req.body?.code);
    if (!challenge || !code) {
      res.status(400).json({ error: "Enter the 6-digit code from your email" });
      return;
    }

    try {
      const result = await redeemLoginChallenge(challenge, code);
      if (!result.ok) {
        // ONE message for every failure. Telling "wrong code" from "no such
        // challenge" would confirm a guessed challenge was real, and "expired"
        // from "wrong" would tell an attacker their timing, not their guess, was
        // the problem. The reason is logged, not sent.
        if (result.reason === "too_many_attempts") {
          req.log.warn("Sign-in code exhausted its attempts — possible brute force");
        }
        res.status(401).json({ error: "That code is not valid. Start again to get a new one." });
        return;
      }

      const [row] = await db.select().from(usersTable).where(eq(usersTable.id, result.userId));
      if (!row) {
        // The account went away between the two steps (deleted mid-login).
        res.status(401).json({ error: "That code is not valid. Start again to get a new one." });
        return;
      }

      await startSession(req, res, row);
      res.json({ user: publicUser(row) });
    } catch (err) {
      req.log.error({ err }, "Sign-in code verification failed");
      res.status(500).json({ error: "Could not sign you in" });
    }
  });

  // ── Log out ──────────────────────────────────────────────────────────────────

  router.post("/account/logout", async (req, res): Promise<void> => {
    // Deleting the session row is what actually revokes it; clearing the cookie
    // alone would leave a stolen copy working until it expired.
    await clearSession(res, getSessionId(req));
    res.json({ ok: true });
  });

  // ── Email verification ───────────────────────────────────────────────────────

}
