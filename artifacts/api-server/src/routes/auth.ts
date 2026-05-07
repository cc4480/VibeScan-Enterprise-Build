import { Router, type IRouter, type Request, type Response } from "express";
import * as client from "openid-client";
import crypto from "crypto";
import { GetCurrentAuthUserResponse } from "@workspace/api-zod";
import {
  getOidcConfig,
  createSession,
  clearSession,
  getSessionId,
  SESSION_COOKIE,
  SESSION_TTL,
} from "../lib/auth";

const router: IRouter = Router();

const PKCE_COOKIE = "oidc_pkce";
const PKCE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function getCallbackUrl(req: Request): string {
  const proto = req.headers["x-forwarded-proto"] ?? req.protocol;
  const host = req.headers["x-forwarded-host"] ?? req.headers["host"];
  return `${proto}://${host}/api/callback`;
}

router.get("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const config = await getOidcConfig();
    const returnTo = typeof req.query["returnTo"] === "string" ? req.query["returnTo"] : "/";

    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();

    const pkcePayload = JSON.stringify({ codeVerifier, state, returnTo });
    const pkceToken = Buffer.from(pkcePayload).toString("base64url");

    res.cookie(PKCE_COOKIE, pkceToken, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: PKCE_TTL_MS,
      secure: req.protocol === "https",
    });

    const callbackUrl = getCallbackUrl(req);

    const authUrl = client.buildAuthorizationUrl(config, {
      redirect_uri: callbackUrl,
      response_type: "code",
      scope: "openid profile email",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    res.redirect(authUrl.href);
  } catch (err) {
    req.log.error({ err }, "Failed to initiate OIDC login");
    res.status(500).send("Login unavailable. Please try again.");
  }
});

router.get("/callback", async (req: Request, res: Response): Promise<void> => {
  try {
    const pkceToken = req.cookies?.[PKCE_COOKIE];
    if (!pkceToken) {
      res.status(400).send("Login session expired. Please try again.");
      return;
    }

    let codeVerifier: string;
    let expectedState: string;
    let returnTo: string;
    try {
      const parsed = JSON.parse(Buffer.from(pkceToken, "base64url").toString("utf-8")) as {
        codeVerifier: string;
        state: string;
        returnTo: string;
      };
      codeVerifier = parsed.codeVerifier;
      expectedState = parsed.state;
      returnTo = parsed.returnTo ?? "/";
    } catch {
      res.status(400).send("Invalid login session. Please try again.");
      return;
    }

    res.clearCookie(PKCE_COOKIE);

    const config = await getOidcConfig();
    const callbackUrl = getCallbackUrl(req);

    const currentUrl = new URL(req.url, `${req.protocol}://${req.headers["host"]}`);

    const tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState,
      redirectUri: callbackUrl,
    });

    const claims = tokens.claims();
    if (!claims?.sub) {
      res.status(400).send("Invalid token response from identity provider.");
      return;
    }

    const profile = tokens.claims() as {
      sub: string;
      email?: string;
      name?: string;
      given_name?: string;
      family_name?: string;
      profile_image_url?: string;
      picture?: string;
    };

    const { db, usersTable } = await import("@workspace/db");
    const { eq } = await import("drizzle-orm");

    await db
      .insert(usersTable)
      .values({
        id: profile.sub,
        email: profile.email ?? null,
        firstName: profile.given_name ?? profile.name?.split(" ")[0] ?? null,
        lastName: profile.family_name ?? profile.name?.split(" ").slice(1).join(" ") ?? null,
        profileImageUrl: profile.profile_image_url ?? profile.picture ?? null,
      })
      .onConflictDoUpdate({
        target: usersTable.id,
        set: {
          email: profile.email ?? null,
          firstName: profile.given_name ?? profile.name?.split(" ")[0] ?? null,
          lastName: profile.family_name ?? profile.name?.split(" ").slice(1).join(" ") ?? null,
          profileImageUrl: profile.profile_image_url ?? profile.picture ?? null,
        },
      });

    const [dbUser] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, profile.sub));

    if (!dbUser) {
      res.status(500).send("Failed to create user record.");
      return;
    }

    const sid = await createSession({
      user: {
        id: dbUser.id,
        email: dbUser.email,
        firstName: dbUser.firstName,
        lastName: dbUser.lastName,
        profileImageUrl: dbUser.profileImageUrl,
      },
      access_token: tokens.access_token ?? crypto.randomBytes(16).toString("hex"),
      refresh_token: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
      expires_at: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined,
    });

    res.cookie(SESSION_COOKIE, sid, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: SESSION_TTL,
      secure: req.protocol === "https",
    });

    const safeReturnTo = returnTo.startsWith("/") ? returnTo : "/";
    res.redirect(safeReturnTo);
  } catch (err) {
    req.log.error({ err }, "OIDC callback failed");
    res.status(500).send("Authentication failed. Please try again.");
  }
});

router.get("/logout", async (req: Request, res: Response): Promise<void> => {
  const sid = getSessionId(req);
  await clearSession(res, sid);
  res.redirect("/");
});

router.get("/auth/user", (req: Request, res: Response) => {
  res.json(
    GetCurrentAuthUserResponse.parse({
      user: req.isAuthenticated() ? req.user : null,
    }),
  );
});

export default router;
