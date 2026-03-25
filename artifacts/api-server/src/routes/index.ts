import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import scansRouter from "./scans";
import reportsRouter from "./reports";
import creditsRouter from "./credits";
import stripeRouter from "./stripe";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(scansRouter);
router.use(reportsRouter);
router.use(creditsRouter);
router.use(stripeRouter);

export default router;
