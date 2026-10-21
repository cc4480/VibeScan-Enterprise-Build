/**
 * Starts Chromium for the scanner, with its sandbox on by default.
 *
 * Chromium's sandbox is the layer that contains a renderer exploit, and the scanner renders attacker-chosen
 * pages, so it is on unless the deployment explicitly sets CHROMIUM_SANDBOX=false. Some container platforms
 * do not let an unprivileged process create the namespaces the sandbox needs; on those the sandboxed launch
 * fails, and the launch repeats without it so the scanner keeps working. That fallback is logged at error
 * level, so an unsandboxed renderer is never silent.
 */
import { logger } from "./logger";
import { CHROMIUM_ARGS, SANDBOXED_ARGS } from "./browserArgs";

interface ChromiumLike<B> {
  launch(opts: { headless: boolean; proxy?: { server: string }; args: string[] }): Promise<B>;
}

/** Sandbox on unless CHROMIUM_SANDBOX is exactly "false". */
export function sandboxEnabled(): boolean {
  return process.env["CHROMIUM_SANDBOX"] !== "false";
}

export async function launchChromium<B>(chromium: ChromiumLike<B>, proxy?: { server: string }): Promise<B> {
  if (sandboxEnabled()) {
    try {
      const browser = await chromium.launch({ headless: true, ...(proxy ? { proxy } : {}), args: [...SANDBOXED_ARGS] });
      logger.info("Chromium started with its sandbox");
      return browser;
    } catch (err) {
      logger.error({ err }, "Chromium would not start with its sandbox; falling back to --no-sandbox (renderer is UNSANDBOXED). Set CHROMIUM_SANDBOX=false to choose this explicitly, or fix the container's user-namespace setup.");
    }
  }
  return chromium.launch({ headless: true, ...(proxy ? { proxy } : {}), args: [...CHROMIUM_ARGS] });
}
