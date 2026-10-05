/**
 * Starts Chromium for the scanner, with its sandbox when the deployment asks for it and can provide it.
 *
 * Off by default: the managed platforms the scanner runs on do not all let an unprivileged container
 * create the namespaces the sandbox needs, and a launch that fails there disables SPA rendering and
 * form login. With CHROMIUM_SANDBOX=true the sandbox is tried first; if Chromium will not start with it
 * the failure is logged at error level and the launch repeats without it, so the scanner keeps working
 * and the log says plainly that the renderer is unsandboxed.
 */
import { logger } from "./logger";
import { CHROMIUM_ARGS, SANDBOXED_ARGS, sandboxRequested } from "./browserArgs";

interface ChromiumLike<B> {
  launch(opts: { headless: boolean; proxy?: { server: string }; args: string[] }): Promise<B>;
}

export async function launchChromium<B>(chromium: ChromiumLike<B>, proxy?: { server: string }): Promise<B> {
  if (sandboxRequested()) {
    try {
      const browser = await chromium.launch({ headless: true, ...(proxy ? { proxy } : {}), args: [...SANDBOXED_ARGS] });
      logger.info("Chromium started with its sandbox");
      return browser;
    } catch (err) {
      logger.error({ err }, "CHROMIUM_SANDBOX=true, but Chromium would not start with its sandbox; falling back to --no-sandbox");
    }
  }
  return chromium.launch({ headless: true, ...(proxy ? { proxy } : {}), args: [...CHROMIUM_ARGS] });
}
