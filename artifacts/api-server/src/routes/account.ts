import { Router, type IRouter } from "express";
import { registerAccountSignup } from "./accountSignup";
import { registerAccountSession } from "./accountSession";
import { registerAccountDelete } from "./accountDelete";
import { registerAccountRecovery } from "./accountRecovery";

/**
 * Email + password accounts.
 *
 * Phase 01 of moving off the anonymous-identity model. Until now a user was a
 * UUID their browser generated and stored in localStorage, sent as a bearer
 * token — which meant scan history died with the browser profile, and there was
 * nowhere safe to keep anything sensitive on a user's behalf.
 *
 * Registering while holding one of those anonymous tokens converts that same
 * row into an account in place. The id never changes, so every scan, report,
 * credit and monitor subscription already pointing at it comes along without
 * migrating a single row — and the bearer token stops working the moment the
 * row has a password (see middlewares/authMiddleware.ts).
 */





const router: IRouter = Router();

registerAccountSignup(router);
registerAccountSession(router);
registerAccountDelete(router);
registerAccountRecovery(router);

export default router;
