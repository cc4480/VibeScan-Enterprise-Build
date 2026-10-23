import type { logger } from "./logger";
import type { checkSslLabs } from "./ssllabs";
import type { runRecon } from "./recon";
import type { createLiveProgress } from "./liveProgress";

/** The per-job child logger. */
export type Log = typeof logger;
export type SslLabsResult = Awaited<ReturnType<typeof checkSslLabs>>;
export type ReconRunResult = Awaited<ReturnType<typeof runRecon>> | null;
export type LiveProgress = ReturnType<typeof createLiveProgress>;
