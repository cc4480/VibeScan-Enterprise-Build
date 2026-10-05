/**
 * Which proxy the headless browsers go through.
 *
 * By default the vetted proxy (vettedProxy.ts), which does the name resolution for Chromium and
 * refuses private answers. An operator's own HTTPS_PROXY/HTTP_PROXY still wins, because some
 * deployments can only reach the internet through one; the browser then resolves nothing itself
 * but the upstream proxy decides, so the address rule is the guard's alone.
 */
import { logger } from "./logger";
import { startVettedProxy, type VettedProxy } from "./vettedProxy";

let started: Promise<VettedProxy> | null = null;

export async function browserProxy(): Promise<{ server: string } | undefined> {
  const configured = process.env["HTTPS_PROXY"] || process.env["HTTP_PROXY"];
  if (configured) {
    logger.warn("HTTPS_PROXY is set: the headless browser uses it and cannot vet the addresses it resolves");
    return { server: configured };
  }
  started ??= startVettedProxy();
  return { server: (await started).server };
}

export async function closeBrowserProxy(): Promise<void> {
  const p = started;
  started = null;
  if (p) await (await p).close().catch(() => {});
}
