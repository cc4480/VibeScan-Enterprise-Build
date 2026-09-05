import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import googleAuthRouter from "./googleAuth";
import scansRouter from "./scans";
import reportsRouter from "./reports";
import creditsRouter from "./credits";
import stripeRouter from "./stripe";
import monitorRouter from "./monitor";
import dismissalsRouter from "./dismissals";
import sharesRouter from "./shares";
import settingsRouter from "./settings";
import accountRouter from "./account";
import oobRouter from "./oob";
import domainVerificationRouter from "./domainVerification";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(googleAuthRouter);
router.use(scansRouter);
router.use(reportsRouter);
router.use(creditsRouter);
router.use(stripeRouter);
router.use(monitorRouter);
router.use(dismissalsRouter);
router.use(sharesRouter);
router.use(settingsRouter);
router.use(accountRouter);
router.use(oobRouter);
router.use(domainVerificationRouter);

export default router;
