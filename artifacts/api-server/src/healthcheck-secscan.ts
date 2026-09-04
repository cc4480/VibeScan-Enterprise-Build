/**
 * Container healthcheck for secscan. Exits 0 while the worker is writing its
 * heartbeat, 1 once it has gone stale.
 *
 * The threshold is four missed writes rather than one: a scanner under load can
 * be briefly busy, and restarting a working process is worse than noticing a
 * dead one a minute late.
 */

import { isHeartbeatFresh } from "./lib/heartbeat";

const MAX_AGE_MS = 60_000;

process.exit(isHeartbeatFresh(MAX_AGE_MS) ? 0 : 1);
