/** Monitoring routes, mounted from the sibling monitor<Part>.ts routers. */
import { Router, type IRouter } from "express";
import { registerMonitorCreate } from "./monitorCreate";
import { registerMonitorList } from "./monitorList";
import { registerMonitorHistory } from "./monitorHistory";
import { registerMonitorPulses } from "./monitorPulses";

const router: IRouter = Router();

registerMonitorCreate(router);
registerMonitorList(router);
registerMonitorHistory(router);
registerMonitorPulses(router);

export default router;
