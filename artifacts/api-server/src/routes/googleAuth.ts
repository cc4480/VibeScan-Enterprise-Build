/**
 * Sign in with Google.
 *
 * Authorization-code flow with PKCE, via the openid-client already used for the
 * legacy Replit OIDC route. Two endpoints:
 *
 *   GET /api/auth/google           → redirect to Google
 *   GET /api/auth/google/callback  → exchange the code, start a session
 *
 * ── Why the email must be verified ──
 * The account is matched by Google's `sub` where one is already linked, and
 * otherwise by email address. Matching on an unverified email would let anyone
 * who can create a Google account claiming an address take over the existing
 * account at that address. So an unverified email is refused outright rather
 * than treated as a weaker signal.
 *
 * ── Why `sub` is stored ──
 * A Google account's email address can change. `sub` never does. Matching on
 * email alone would quietly follow the address to whoever holds it next; storing
 * `sub` on first sign-in pins the account to the identity rather than the label.
 *
 * ── What this deliberately does not do ──
 * It does not adopt an anonymous visitor's scan history. Registration can,
 * because it happens on a request carrying that visitor's bearer token, which
 * proves possession. A Google sign-in arrives as a top-level browser redirect
 * with no such proof, and accepting an id from the query string would let anyone
 * claim someone else's history by guessing it. Anonymous users who sign in with
 * Google therefore start with an empty account; a "claim my earlier scans" flow
 * needs to be its own authenticated step.
 */

import { Router, type IRouter, type Request, type Response } from "express";
import * as client from "openid-client";
import { eq } from "drizzle-orm";
import { db, usersTable } from "@workspace/db";
import { createSession, SESSION_COOKIE, SESSION_TTL } from "../lib/auth";
import { clientIp } from "../lib/clientIp";
import { addToMarketingAudience, sendWelcomeEmail } from "../lib/mailer";

const router: IRouter = Router();

const GOOGLE_ISSUER = "https://accounts.google.com";
const PKCE_COOKIE = "g_pkce";
const PKCE_TTL_MS = 10 * 60_000;

function googleConfigured(): boolean {
  return Boolean(
    process.env["GOOGLE_CLIENT_ID"] && process.env["GOOGLE_CLIENT_SECRET"],
  );
}

/**
 * Built from APP_ORIGIN rather than the request. A redirect URI derived from
 * Host or X-Forwarded-Host is attacker-influenceable, and it must in any case
 * match the value registered in Google Cloud Console exactly — so it should
 * come from configuration, not from whoever is calling.
 */
function callbackUrl(): string {
  const origin = (process.env["APP_ORIGIN"] ?? "").replace(/\/$/, "");
  return `${origin}/api/auth/google/callback`;
}

let cachedConfig: client.Configuration | null = null;

async function getGoogleConfig(): Promise<client.Configuration> {
  if (!cachedConfig) {
    cachedConfig = await client.discovery(
      new URL(GOOGLE_ISSUER),
      process.env["GOOGLE_CLIENT_ID"]!,
      process.env["GOOGLE_CLIENT_SECRET"]!,
    );
  }
  return cachedConfig;
}

// Same shape as the limiter on /login and the account routes: in-memory,
// per-instance, enough to stop a loop rather than a determined attacker.
const attempts = new Map<string, number[]>();
const WINDOW_MS = 15 * 60_000;
const MAX_ATTEMPTS = 20;

function rateLimited(key: string): boolean {
  const now = Date.now();
  const recent = (attempts.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  attempts.set(key, recent);
  return recent.length > MAX_ATTEMPTS;
}

/** Only ever redirect within our own site. */
function safeReturnTo(raw: unknown): string {
  if (typeof raw !== "string" || !raw.startsWith("/")) return "/";
  // Reject protocol-relative targets ("//evil.example"), which are same-origin
  // to a naive startsWith check but leave the site.
  if (raw.startsWith("//")) return "/";
  return raw;
}

// ── GET /api/auth/google ─────────────────────────────────────────────────────
router.get("/auth/google", async (req: Request, res: Response): Promise<void> => {
  if (!googleConfigured()) {
    res.status(503).send("Google sign-in is not configured.");
    return;
  }
  if (rateLimited(`google:${clientIp(req)}`)) {
    res.status(429).send("Too many sign-in attempts. Please try again shortly.");
    return;
  }

  try {
    const config = await getGoogleConfig();
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();

    const payload = JSON.stringify({
      codeVerifier,
      state,
      returnTo: safeReturnTo(req.query["returnTo"]),
    });

    res.cookie(PKCE_COOKIE, Buffer.from(payload).toString("base64url"), {
      httpOnly: true,
      sameSite: "lax", // must survive the top-level redirect back from Google
      maxAge: PKCE_TTL_MS,
      secure: req.protocol === "https",
      path: "/api/auth/google",
    });

    const authUrl = client.buildAuthorizationUrl(config, {
      redirect_uri: callbackUrl(),
      scope: "openid email profile",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    res.redirect(authUrl.href);
  } catch (err) {
    req.log.error({ err }, "Could not start Google sign-in");
    res.status(500).send("Sign-in unavailable. Please try again.");
  }
});

// ── GET /api/auth/google/callback ────────────────────────────────────────────
router.get(
  "/auth/google/callback",
  async (req: Request, res: Response): Promise<void> => {
    if (!googleConfigured()) {
      res.status(503).send("Google sign-in is not configured.");
      return;
    }

    const raw = req.cookies?.[PKCE_COOKIE] as string | undefined;
    res.clearCookie(PKCE_COOKIE, { path: "/api/auth/google" });

    if (!raw) {
      res.status(400).send("Sign-in session expired. Please start again.");
      return;
    }

    let codeVerifier: string;
    let expectedState: string;
    let returnTo: string;
    try {
      const parsed = JSON.parse(Buffer.from(raw, "base64url").toString()) as {
        codeVerifier: string;
        state: string;
        returnTo: string;
      };
      codeVerifier = parsed.codeVerifier;
      expectedState = parsed.state;
      returnTo = safeReturnTo(parsed.returnTo);
    } catch {
      res.status(400).send("Sign-in session was malformed. Please start again.");
      return;
    }

    try {
      const config = await getGoogleConfig();

      // The URL openid-client validates against must be the registered redirect
      // URI plus the query Google appended, not a reconstruction from headers.
      const current = new URL(callbackUrl());
      for (const [k, v] of Object.entries(req.query)) {
        if (typeof v === "string") current.searchParams.set(k, v);
      }

      const tokens = await client.authorizationCodeGrant(config, current, {
        pkceCodeVerifier: codeVerifier,
        expectedState,
      });

      const claims = tokens.claims();
      const sub = claims?.["sub"];
      const email = claims?.["email"];
      const emailVerified = claims?.["email_verified"];

      if (typeof sub !== "string" || typeof email !== "string") {
        req.log.warn("Google returned no sub or email");
        res.status(400).send("Google did not return an email address.");
        return;
      }

      // See the note at the top: an unverified address cannot be used to match
      // an existing account, and we have no use for one that cannot.
      if (emailVerified !== true) {
        req.log.warn({ email }, "Google sign-in refused: email not verified");
        res
          .status(400)
          .send(
            "Your Google account's email address is not verified, so it cannot " +
              "be used to sign in here.",
          );
        return;
      }

      const normalizedEmail = email.trim().toLowerCase();
      const firstName = typeof claims["given_name"] === "string" ? claims["given_name"] : null;
      const lastName = typeof claims["family_name"] === "string" ? claims["family_name"] : null;
      const picture = typeof claims["picture"] === "string" ? claims["picture"] : null;

      // 1. Already linked to this Google identity.
      let [row] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.googleSub, sub))
        .limit(1);

      // 2. Otherwise an existing account at this verified address — link it.
      if (!row) {
        const [byEmail] = await db
          .select()
          .from(usersTable)
          .where(eq(usersTable.email, normalizedEmail))
          .limit(1);

        if (byEmail) {
          if (byEmail.googleSub && byEmail.googleSub !== sub) {
            // Two Google identities claiming one address should not silently
            // swap ownership of the account.
            req.log.warn({ email: normalizedEmail }, "Google sub conflict on existing account");
            res.status(409).send("This email is already linked to a different Google account.");
            return;
          }
          [row] = await db
            .update(usersTable)
            .set({
              googleSub: sub,
              // Google has verified this address, so an account that had not yet
              // confirmed its email is confirmed by signing in this way.
              emailVerifiedAt: byEmail.emailVerifiedAt ?? new Date(),
              firstName: byEmail.firstName ?? firstName,
              lastName: byEmail.lastName ?? lastName,
              profileImageUrl: byEmail.profileImageUrl ?? picture,
            })
            .where(eq(usersTable.id, byEmail.id))
            .returning();
        }
      }

      // 3. Otherwise a new account.
      if (!row) {
        [row] = await db
          .insert(usersTable)
          .values({
            email: normalizedEmail,
            googleSub: sub,
            emailVerifiedAt: new Date(),
            firstName,
            lastName,
            profileImageUrl: picture,
          })
          .returning();

        // Best-effort, fire-and-forget: only for a genuinely new account, not
        // every Google sign-in. Each function logs and swallows its own errors.
        if (row) {
          void addToMarketingAudience(normalizedEmail, firstName);
          void sendWelcomeEmail(normalizedEmail, firstName);
        }
      }

      if (!row) {
        res.status(500).send("Could not create your account. Please try again.");
        return;
      }

      const sid = await createSession({
        user: {
          id: row.id,
          email: row.email,
          firstName: row.firstName,
          lastName: row.lastName,
          profileImageUrl: row.profileImageUrl,
        },
        // The session store's shape requires this; Google's access token is of
        // no use to us after the exchange, so nothing is kept.
        access_token: "",
      });

      res.cookie(SESSION_COOKIE, sid, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: SESSION_TTL,
        secure: req.protocol === "https",
      });

      req.log.info({ userId: row.id }, "Signed in with Google");
      res.redirect(returnTo);
    } catch (err) {
      req.log.error({ err }, "Google sign-in callback failed");
      res.status(400).send("Sign-in failed. Please try again.");
    }
  },
);

/** Exported for the route index to report configuration state. */
export { googleConfigured };

export default router;
