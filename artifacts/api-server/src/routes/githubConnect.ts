/**
 * Connect GitHub, so a scan can read private repositories the person chooses.
 *
 *   GET    /api/github/connect                  → GitHub's install page for the App (pick repositories there)
 *   GET    /api/github/callback                 ← GitHub returns here (the App's Callback URL and Setup URL)
 *   GET    /api/github/repos                    → the repositories this account's connections can read
 *   DELETE /api/github/installations/:id        → forget one connection
 *
 * The return trip is checked like Google sign-in's: a random state in a short-lived, path-scoped, HttpOnly cookie
 * must match the state GitHub hands back, and the cookie must belong to the account that is signed in now. Which
 * installations are then recorded is decided by GitHub alone (lib/githubConnect.ts), never by the request.
 */
import { Router, type IRouter, type Request, type Response } from "express";
import { randomBytes } from "node:crypto";
import { githubAppConfig, installUrl } from "../lib/githubApp";
import {
  GithubConnectError,
  authorizeUrl,
  connectConfigured,
  exchangeCode,
  githubClientConfig,
  installationRepositories,
  userInstallations,
} from "../lib/githubConnect";
import { linkedInstallations, removeLink, saveLinks } from "../lib/githubLinks";

const router: IRouter = Router();

const COOKIE = "gh_connect";
const COOKIE_PATH = "/api/github";
const TTL_MS = 15 * 60 * 1000;
const SIGN_IN = "/sign-in?returnTo=%2Fscan";

/** Back to the scan page with a one-word outcome the page turns into a message. */
const backToScan = (res: Response, outcome: "connected" | "none" | "expired" | "unavailable" | "error") =>
  res.redirect(`/scan?github=${outcome}`);

function readCookie(req: Request): { state: string; userId: string } | null {
  const raw = req.cookies?.[COOKIE] as string | undefined;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString()) as { state?: unknown; userId?: unknown };
    return typeof parsed.state === "string" && typeof parsed.userId === "string" ? { state: parsed.state, userId: parsed.userId } : null;
  } catch {
    return null;
  }
}

router.get("/github/connect", (req: Request, res: Response): void => {
  if (!req.isAuthenticated()) {
    res.redirect(SIGN_IN);
    return;
  }
  const app = githubAppConfig();
  const target = installUrl(app, "placeholder");
  if (!connectConfigured() || !target) {
    req.log.error("Connect GitHub attempted but the GitHub App or its OAuth client is not configured");
    backToScan(res, "unavailable");
    return;
  }
  const state = randomBytes(24).toString("base64url");
  res.cookie(COOKIE, Buffer.from(JSON.stringify({ state, userId: req.user.id })).toString("base64url"), {
    httpOnly: true,
    sameSite: "lax", // must survive the top-level redirect back from GitHub
    maxAge: TTL_MS,
    secure: req.protocol === "https",
    path: COOKIE_PATH,
  });
  res.redirect(installUrl(app, state)!);
});

router.get("/github/callback", async (req: Request, res: Response): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.redirect(SIGN_IN);
    return;
  }
  const started = readCookie(req);
  const state = typeof req.query["state"] === "string" ? req.query["state"] : "";
  // A return trip this browser did not start, for this account, is refused: that is what stops a link crafted by
  // someone else from attaching their installation (or a stranger's) to this account.
  if (!started || started.userId !== req.user.id || !state || state !== started.state) {
    res.clearCookie(COOKIE, { path: COOKIE_PATH });
    backToScan(res, "expired");
    return;
  }

  const client = githubClientConfig();
  const app = githubAppConfig();
  if (!client || !app) {
    res.clearCookie(COOKIE, { path: COOKIE_PATH });
    backToScan(res, "unavailable");
    return;
  }

  const code = typeof req.query["code"] === "string" ? req.query["code"] : "";
  if (!code) {
    // Installed or updated without being asked to authorise (the App was already installed, say). Ask GitHub to
    // authorise now with the same state, so the proof below can still be had. The cookie stays for that trip.
    res.redirect(authorizeUrl(client, started.state));
    return;
  }
  res.clearCookie(COOKIE, { path: COOKIE_PATH });

  try {
    const userToken = await exchangeCode(code, client);
    // The user token is used for this one call and goes out of scope here; it is not stored or logged.
    const installs = await userInstallations(userToken, app.appId);
    if (installs.length === 0) {
      backToScan(res, "none");
      return;
    }
    await saveLinks(req.user.id, installs);
    req.log.info({ installations: installs.length }, "GitHub connected");
    backToScan(res, "connected");
  } catch (err) {
    req.log.warn({ reason: err instanceof GithubConnectError ? err.reason : "unknown" }, "Connect GitHub failed");
    backToScan(res, "error");
  }
});

router.get("/github/repos", async (req: Request, res: Response): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const connections = await linkedInstallations(req.user.id);
  const app = githubAppConfig();
  const repositories = (await Promise.all(connections.map((c) => installationRepositories(c.installationId, app))))
    .flat()
    .sort((a, b) => a.fullName.localeCompare(b.fullName));
  res.json({ available: connectConfigured(), connections, repositories });
});

router.delete("/github/installations/:id", async (req: Request, res: Response): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const id = Number(req.params["id"]);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: "Not a GitHub installation id." });
    return;
  }
  const removed = await removeLink(req.user.id, id);
  res.status(removed ? 200 : 404).json({ removed });
});

export default router;
