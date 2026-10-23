import type { Express } from "express";
import { AI_WIDGET_JS, AI_CHAT_CLEAN_JS } from "./ai-assets.js";
import { SECRETS_JS, OPENAPI_SPEC, STRIPE_SOURCEMAP_KEY } from "./secrets.js";

/** robots.txt, the OpenAPI document and the JavaScript bundles. */


export function mountAssets(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // robots.txt — discloses sensitive-looking paths (probes.ts checkRobotsTxt).
  // No security.txt anywhere: that finding is "missing", so it is earned by
  // omission, not a route.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/robots.txt", (_req, res) => {
    res.type("text/plain").send(
      "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /internal-api\nDisallow: /.env\nDisallow: /staging\n",
    );
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Root OpenAPI doc — apiDocsProbe.ts "Exposed API Documentation".
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/openapi.json", (_req, res) => res.json(OPENAPI_SPEC));

  // ─────────────────────────────────────────────────────────────────────────────
  // JS bundle — secret-pattern-data.ts (jsScanner), external-file path, plus a
  // source map reference (sourceMaps.ts) whose map embeds a secret too.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/assets/ai-widget.js", (_req, res) => { res.type("application/javascript").send(AI_WIDGET_JS); });
  app.get("/assets/ai-chat.js", (_req, res) => { res.type("application/javascript").send(AI_CHAT_CLEAN_JS); });
  app.get("/assets/app.js", (_req, res) => {
    res.type("application/javascript").send(SECRETS_JS + "\n//# sourceMappingURL=/assets/app.js.map\n");
  });
  app.get("/assets/app.js.map", (_req, res) => {
    res.json({
      version: 3,
      sources: ["src/app.ts", "src/billing.ts"],
      sourcesContent: [
        "export const a = 1;",
        `export const STRIPE_SECRET = '${STRIPE_SOURCEMAP_KEY}';`,
      ],
      mappings: "AAAA",
    });
  });
}
