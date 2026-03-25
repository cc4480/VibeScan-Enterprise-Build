import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import scansRouter from "./scans";
import reportsRouter from "./reports";
import creditsRouter from "./credits";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(scansRouter);
router.use(reportsRouter);
router.use(creditsRouter);

export default router;
