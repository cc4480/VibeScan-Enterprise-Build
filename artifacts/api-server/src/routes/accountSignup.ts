import { type IRouter } from "express";
import { RegisterBody, UUID_V4, attempts, isRateLimited, maskEmail, publicUser, startSession } from "./accountShared";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { hashPassword } from "../lib/password";
import { LOGIN_CODE_TTL_MS, generateChallenge, normalizeLoginCode } from "../lib/loginCode";
import { abandonRegistration, issueRegistrationChallenge, redeemRegistrationChallenge } from "../lib/pendingRegistration";
import { NETWORK_LIMIT_MESSAGE, networkKey, networkMaySignUp } from "../lib/signupNetwork";
import { sendLoginCode, addToMarketingAudience, sendWelcomeEmail, sendSignupExistingAccountEmail } from "../lib/mailer";
import { clientIp } from "../lib/clientIp";

/** Registration: details, then the emailed code that creates the account. */



export function registerAccountSignup(router: IRouter): void {
  // ── Register (step 1 of 2: details) ──────────────────────────────────────────
  //
  // No account exists yet. This checks the details and the per-network cap, then
  // emails a six-digit code; POST /account/register/verify creates the account
  // only when that code comes back. An address nobody can read therefore never
  // becomes an account, never receives free scans, and never blocks its real
  // owner with "already exists". See lib/pendingRegistration.ts and
  // lib/signupNetwork.ts.
  //
  // THE REPLY IS THE SAME WHETHER OR NOT THE ADDRESS ALREADY HAS AN ACCOUNT.
  // Answering "already exists" would let anyone test who is registered, one
  // request per address. Instead an existing address gets the same 202 and a
  // challenge of the same shape, and its owner is emailed (see
  // sendSignupExistingAccountEmail) that someone tried, that nothing changed,
  // and how to sign in. That challenge is not stored: nothing it could be
  // redeemed against exists, so POST /account/register/verify answers it with
  // the same 401 as a wrong code. The existing account is read and never
  // written, and no session is started.
  //
  // What has to match, step by step:
  //   - status and body shape: 202 { codeRequired, challenge, sentTo }, with
  //     sentTo masked from the submitted address, which the caller already has;
  //   - the refusals: the network cap and the per-address cap come BEFORE the
  //     lookup, so a capped network or a hammered address is refused the same
  //     way for both, and a failed send is the same 502 for both;
  //   - the work: both paths hash the password (the slow part), look up the
  //     legacy identity and send one email, so the time does not tell them apart.

  router.post("/account/register", async (req, res): Promise<void> => {
    if (isRateLimited(`register:${clientIp(req)}`)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }

    const parsed = RegisterBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join(", ") });
      return;
    }
    const { email, password } = parsed.data;

    // Per ADDRESS as well as per IP. Every request that gets past here sends a
    // message to `email` (a code, or the notice that it already has an account),
    // so without this a script rotating IPs could mail one person without limit.
    // Applied before any lookup, so it says nothing about the address.
    if (isRateLimited(`register-email:${email}`)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }

    try {
      // Checked BEFORE a code is sent, so a capped network cannot use sign-up to
      // mail codes to arbitrary addresses either. And before the lookup for an
      // existing account, so a capped network is refused this way for every
      // address rather than only for new ones.
      const network = networkKey(clientIp(req));
      if (!(await networkMaySignUp(network))) {
        req.log.warn("Sign-up refused: network account limit reached");
        res.status(429).json({ error: NETWORK_LIMIT_MESSAGE });
        return;
      }

      const [existing] = await db.select().from(usersTable).where(eq(usersTable.email, email));

      // A legacy anonymous identity to promote in place when the account is
      // created, so its scans follow the user. Captured now because step two may
      // arrive without it. Looked up for an existing address too, only so the
      // two paths do the same work; the result is not used there.
      const bearer = req.headers["authorization"]?.startsWith("Bearer ")
        ? req.headers["authorization"].slice(7).trim()
        : undefined;
      let anonUserId: string | null = null;
      if (bearer && UUID_V4.test(bearer)) {
        const [anon] = await db.select().from(usersTable).where(eq(usersTable.id, bearer));
        if (anon && !anon.passwordHash && !anon.email) anonUserId = anon.id;
      }

      // Hashed on both paths: it is the slow step, and skipping it for an
      // existing address would make the reply time say whether one exists.
      const passwordHash = await hashPassword(password);

      if (existing) {
        // Awaited and failing exactly as the code send below does.
        try {
          await sendSignupExistingAccountEmail(email);
        } catch (err) {
          req.log.error({ err }, "Could not send sign-up notice");
          res.status(502).json({ error: "Could not send your code. Please try again shortly." });
          return;
        }
        res.status(202).json({ codeRequired: true, challenge: generateChallenge(), sentTo: maskEmail(email) });
        return;
      }

      const { challenge, code } = await issueRegistrationChallenge({
        email,
        passwordHash,
        signupNetwork: network,
        anonUserId,
      });

      // Awaited and not swallowed, as for sign-in: the email IS the next step.
      try {
        await sendLoginCode(email, code, Math.round(LOGIN_CODE_TTL_MS / 60000));
      } catch (err) {
        await abandonRegistration(email);
        req.log.error({ err }, "Could not send sign-up code");
        res.status(502).json({ error: "Could not send your code. Please try again shortly." });
        return;
      }

      res.status(202).json({ codeRequired: true, challenge, sentTo: maskEmail(email) });
    } catch (err) {
      req.log.error({ err }, "Registration failed");
      res.status(500).json({ error: "Could not create the account" });
    }
  });

  // ── Register (step 2 of 2: emailed code) ─────────────────────────────────────

  router.post("/account/register/verify", async (req, res): Promise<void> => {
    if (isRateLimited(`register2fa:${clientIp(req)}`)) {
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
      const result = await redeemRegistrationChallenge(challenge, code);
      if (!result.ok) {
        if (result.reason === "too_many_attempts") {
          req.log.warn("Sign-up code exhausted its attempts — possible brute force");
        }
        res.status(401).json({ error: "That code is not valid. Start again to get a new one." });
        return;
      }
      const { pending } = result;

      // Both re-checked: another sign-up could have taken the address, or the
      // network's allowance, in the ten minutes since step one.
      //
      // This 409 is not an account-existence oracle, unlike the one step one
      // used to give: it is reachable only by returning a valid code, and a code
      // is only ever mailed to the address itself. Whoever sees it can already
      // read that mailbox, where the notice email tells them the same.
      const [existing] = await db.select().from(usersTable).where(eq(usersTable.email, pending.email));
      if (existing) {
        res.status(409).json({ error: "An account with that email already exists" });
        return;
      }
      if (pending.signupNetwork && !(await networkMaySignUp(pending.signupNetwork))) {
        res.status(429).json({ error: NETWORK_LIMIT_MESSAGE });
        return;
      }

      // The code proves the mailbox, so the address is verified from the start.
      const fields = {
        email: pending.email,
        passwordHash: pending.passwordHash,
        emailVerifiedAt: new Date(),
        signupNetwork: pending.signupNetwork,
      };

      let row: typeof usersTable.$inferSelect | undefined;
      if (pending.anonUserId) {
        const [anon] = await db.select().from(usersTable).where(eq(usersTable.id, pending.anonUserId));
        // Only claim a row that is still genuinely anonymous.
        if (anon && !anon.passwordHash && !anon.email) {
          [row] = await db.update(usersTable).set(fields).where(eq(usersTable.id, anon.id)).returning();
        }
      }
      if (!row) {
        [row] = await db.insert(usersTable).values(fields).returning();
      }
      if (!row) {
        res.status(500).json({ error: "Could not create the account" });
        return;
      }

      // Best-effort, fire-and-forget; each logs and swallows its own errors.
      void addToMarketingAudience(pending.email);
      void sendWelcomeEmail(pending.email);

      await startSession(req, res, row);
      res.status(201).json({ user: publicUser(row) });
    } catch (err) {
      req.log.error({ err }, "Registration verification failed");
      res.status(500).json({ error: "Could not create the account" });
    }
  });

  // ── Log in (step 1 of 2: password) ───────────────────────────────────────────
  //
  // A correct password no longer signs anyone in. It produces a CHALLENGE and an
  // emailed six-digit code; POST /account/login/verify exchanges the two for a
  // session. That is what makes this two-factor rather than one factor with extra
  // steps: the password is something you know, the code proves you can read the
  // account's mailbox, and neither alone gets you a session.
  //
  // See lib/loginCode.ts for why a six-digit secret is safe here at all.

}
