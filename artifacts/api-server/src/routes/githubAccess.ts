import { Router, type IRouter } from "express";
import { parseGithubRepoRef } from "../lib/githubSourceProbe";
import { diagnoseAccess } from "../lib/githubInstallationAccess";
import { linkedInstallationIds } from "../lib/githubLinks";

const router: IRouter = Router();

/**
 * "Why can't I scan my private repository?" Signed-in only. It reports which step of getting access stopped (whether
 * the account is listed, whether the App's key works, what GitHub says covers the repository, whether a token could be
 * minted) and contains no key and no token. GitHub is contacted only for an account listed as an installation owner.
 */
router.get("/github/access-check", async (req, res) => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const ref = parseGithubRepoRef(String(req.query["repo"] ?? ""));
  if (!ref) {
    res.status(400).json({ error: "Pass ?repo=https://github.com/owner/repo" });
    return;
  }
  res.json(await diagnoseAccess({ email: req.user.email, repo: { owner: ref.owner, repo: ref.repo }, linked: await linkedInstallationIds(req.user.id) }));
});

export default router;
