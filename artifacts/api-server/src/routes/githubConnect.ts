/**
 * Connect GitHub, so a scan can read private repositories the person chooses.
 *
 *   GET    /api/github/connect[?manage=1]       → GitHub's sign-in for the App, to find installations that already exist
 *   GET    /api/github/callback                 ← GitHub returns here (the App's Callback URL and Setup URL)
 *   GET    /api/github/repos                    → the repositories this account's connections can read
 *   DELETE /api/github/installations/:id        → forget one connection
 *
 * The trip, in order: (1) authorise, so GitHub says which installations of the App this person can use, and an
 * existing one is connected straight away, with no install page and no Setup URL needed to find the way back; (2) only
 * if there is none, the install page, where they choose repositories; (3) back here, authorise once more, and list again.
 * The cookie's `stage` is what stops that from looping: a second empty answer is "none", not another trip.
 *
 * The return trip is checked like Google sign-in's: a random state in a short-lived, path-scoped, HttpOnly cookie
 * must match the state GitHub hands back, and the cookie must belong to the account that is signed in now. Which
 * installations are then recorded is decided by GitHub alone (lib/githubConnect.ts), never by the request.
 */
import { Router, type IRouter, type Request, type Response } from "express";
import { randomBytes } from "node:crypto";
import { githubAppConfig, installUrl } from "../lib/githubApp";
import { APP_ORIGIN } from "../lib/appOrigin";
import {
  GithubConnectError,
  authorizeUrl,
  connectConfigured,
  exchangeCode,
  githubClientConfig,
  installationRepositoryList,
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

type Stage = "start" | "installing";

function readCookie(req: Request): { state: string; userId: string; stage: Stage } | null {
  const raw = req.cookies?.[COOKIE] as string | undefined;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString()) as { state?: unknown; userId?: unknown; stage?: unknown };
    return typeof parsed.state === "string" && typeof parsed.userId === "string"
      ? { state: parsed.state, userId: parsed.userId, stage: parsed.stage === "installing" ? "installing" : "start" }
      : null;
  } catch {
    return null;
  }
}

function setCookie(req: Request, res: Response, state: string, userId: string, stage: Stage): void {
  res.cookie(COOKIE, Buffer.from(JSON.stringify({ state, userId, stage })).toString("base64url"), {
    httpOnly: true,
    sameSite: "lax", // must survive the top-level redirect back from GitHub
    maxAge: TTL_MS,
    secure: req.protocol === "https",
    path: COOKIE_PATH,
  });
}

/** The address GitHub returns to after authorising: one of the App's Callback URLs. */
const CALLBACK_URL = () => `${APP_ORIGIN}/api/github/callback`;

router.get("/github/connect", (req: Request, res: Response): void => {
  if (!req.isAuthenticated()) {
    res.redirect(SIGN_IN);
    return;
  }
  const app = githubAppConfig();
  const client = githubClientConfig();
  const target = installUrl(app, "placeholder");
  if (!connectConfigured() || !target || !client) {
    req.log.error("Connect GitHub attempted but the GitHub App or its OAuth client is not configured");
    backToScan(res, "unavailable");
    return;
  }
  const state = randomBytes(24).toString("base64url");
  // "Add or change repositories" (?manage=1): the person is already connected and wants GitHub's own page for choosing
  // repositories, so go there directly. They return through the App's Setup URL, authorise, and are listed again.
  if (req.query["manage"] === "1") {
    setCookie(req, res, state, req.user.id, "installing");
    res.redirect(target.replace("placeholder", encodeURIComponent(state)));
    return;
  }
  setCookie(req, res, state, req.user.id, "start");
  // Authorise first. Someone who already installed the App is recognised here and returned at once; only someone with
  // nothing to find is sent on to the install page (see the callback).
  res.redirect(authorizeUrl(client, state, CALLBACK_URL()));
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
    res.redirect(authorizeUrl(client, started.state, CALLBACK_URL()));
    return;
  }

  // The cookie is cleared only when the trip ends here; on the way to the install page it is replaced instead.
  const finish = (outcome: "connected" | "none" | "error"): void => {
    res.clearCookie(COOKIE, { path: COOKIE_PATH });
    backToScan(res, outcome);
  };

  try {
    const userToken = await exchangeCode(code, client);
    // The user token is used for this one call and goes out of scope here; it is not stored or logged.
    const installs = await userInstallations(userToken, app.appId);
    if (installs.length === 0) {
      // First time through with nothing installed: send them to install the App and choose repositories. They come
      // back here (no code), authorise again, and are listed again; a second empty answer is a real "none".
      const install = started.stage === "start" ? installUrl(app, started.state) : null;
      if (install) {
        setCookie(req, res, started.state, req.user.id, "installing");
        res.redirect(install);
        return;
      }
      finish("none");
      return;
    }
    await saveLinks(req.user.id, installs);
    req.log.info({ installations: installs.length }, "GitHub connected");
    finish("connected");
  } catch (err) {
    req.log.warn({ reason: err instanceof GithubConnectError ? err.reason : "unknown" }, "Connect GitHub failed");
    finish("error");
  }
});

router.get("/github/repos", async (req: Request, res: Response): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const links = await linkedInstallations(req.user.id);
  const app = githubAppConfig();
  const listed = await Promise.all(links.map((c) => installationRepositoryList(c.installationId, app)));
  // Each connection says how it stands, so an uninstalled App or an unreachable GitHub is not shown as "nothing shared".
  const connections = links.map((c, i) => ({ ...c, status: listed[i]!.status, repositoryCount: listed[i]!.repositories.length }));
  const repositories = listed.flatMap((l) => l.repositories).sort((a, b) => a.fullName.localeCompare(b.fullName));
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
