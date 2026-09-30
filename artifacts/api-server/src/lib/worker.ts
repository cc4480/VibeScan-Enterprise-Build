/**
 * pg-boss worker — processes scan jobs from the queue.
 * Registered at startup by index.ts.
 *
 * Job lifecycle per scan:
 *   queued → scanning → analyzing → complete
 *              ↓ (on error)
 *            failed
 */
export { processScanJob } from "./workerJob";
export { resolveNextScanAt } from "./workerCadence";
export { startWorker } from "./workerQueue";
