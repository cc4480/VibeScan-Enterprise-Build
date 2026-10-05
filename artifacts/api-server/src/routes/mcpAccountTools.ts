import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Request } from "express";
import type { TokenUser } from "../lib/apiTokens";
import { text, hostOf, formatAccount, formatVerification } from "./mcpFormat";
import { z } from "zod";
import { db, scansTable, domainVerificationsTable } from "@workspace/db";
import { and, desc, eq, ne } from "drizzle-orm";
import { runAppRoute } from "./appRouteRunner";
import { verificationIsCurrent } from "../lib/activeProbeGate";
import domainVerificationRouter from "./domainVerification";
import checkoutRouter from "./checkout";
import { APP_ORIGIN } from "../lib/appOrigin";

/** MCP tools for recent scans, verified domains, the account, and domain verification. */
export function registerAccountTools(server: McpServer, httpReq: Request, user: TokenUser): void {
  server.registerTool(
    "list_recent_scans",
    {
      title: "List recent scans",
      description: "The user's most recent scans with their status, newest first.",
      inputSchema: { limit: z.number().int().min(1).max(25).optional() },
      annotations: { readOnlyHint: true },
    },
    async ({ limit }) => {
      const rows = await db
        .select({ id: scansTable.id, targetUrl: scansTable.targetUrl, status: scansTable.status, createdAt: scansTable.createdAt })
        .from(scansTable)
        // Re-checks of a single finding (origin "verify") are not scans the person asked for; they appear on the finding.
        .where(and(eq(scansTable.userId, user.id), ne(scansTable.origin, "verify")))
        .orderBy(desc(scansTable.createdAt))
        .limit(limit ?? 10);
      if (rows.length === 0) return text("No scans yet.");
      return text(rows.map((r) => `${r.id}  ${r.status.padEnd(9)}  ${r.createdAt.toISOString()}  ${r.targetUrl}`).join("\n"));
    },
  );

  server.registerTool(
    "list_verified_domains",
    {
      title: "List verified domains",
      description:
        "Domains the user has proved they own. Only these receive active testing (injection, XSS, SSRF, access control); " +
        `others get passive checks. Verify more at ${APP_ORIGIN}/domains.`,
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const rows = await db
        .select({ domain: domainVerificationsTable.domain })
        .from(domainVerificationsTable)
        // The same test the active-probe gate applies (lib/activeProbeGate.ts):
        // a verification counts while the proof was last seen within the
        // validity window. Exact hostname only.
        .where(and(eq(domainVerificationsTable.userId, user.id), verificationIsCurrent()));
      const verified = rows.map((r) => r.domain);
      return text(
        verified.length
          ? `Verified (full active testing): ${verified.join(", ")}`
          : `No verified domains yet — scans get passive checks only. Verify one at ${APP_ORIGIN}/domains.`,
      );
    },
  );

  // ── Account ──────────────────────────────────────────────────────────────

  server.registerTool(
    "get_account",
    {
      title: "Scans left and plan",
      description:
        "How many scans the user can still run — free scans, plan scans and credits — and their plan. " +
        "Check this before starting several scans.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const { status, body } = await runAppRoute(checkoutRouter, "get", "/billing/status", httpReq, user);
      if (status >= 400) return text(String(body?.error ?? "Could not read the account."), true);
      return text(formatAccount(body));
    },
  );

  // ── Domain verification ──────────────────────────────────────────────────

  server.registerTool(
    "start_domain_verification",
    {
      title: "Start verifying a domain",
      description:
        "Begin proving the user owns a domain, which unlocks active tests (injection, XSS, SSRF, access control) on its scans. " +
        "Returns a file to publish on the site, or a DNS TXT record — an editor can usually add the file to the codebase " +
        "and deploy it. Then call check_domain_verification. Calling it again returns the same token, so a record already published stays valid.",
      inputSchema: { domain: z.string().min(1).max(253).describe("The domain, e.g. example.com or https://example.com") },
      annotations: { idempotentHint: false },
    },
    async ({ domain }) => {
      const { status, body } = await runAppRoute(domainVerificationRouter, "post", "/domain-verifications", httpReq, user, {
        body: { domain },
      });
      if (status >= 400) return text(String(body?.error ?? "Could not start verification."), true);
      return text(formatVerification(body.verification));
    },
  );

  server.registerTool(
    "check_domain_verification",
    {
      title: "Check a domain verification",
      description:
        "Check whether the file or DNS record from start_domain_verification is live. On success the domain is verified " +
        "and its next scan includes active tests. DNS changes can take a few minutes.",
      inputSchema: { domain: z.string().min(1).max(253).describe("The domain passed to start_domain_verification") },
      annotations: { idempotentHint: true, openWorldHint: true },
    },
    async ({ domain }) => {
      const { status, body } = await runAppRoute(
        domainVerificationRouter,
        "post",
        "/domain-verifications/:domain/check",
        httpReq,
        user,
        { params: { domain: hostOf(domain) } },
      );
      if (status === 409 && body?.verification) {
        return text(`Not found yet. ${body.detail ?? ""}\n\n${formatVerification(body.verification)}`, true);
      }
      if (status >= 400) return text(String(body?.error ?? "Could not check verification."), true);
      return text(formatVerification(body.verification));
    },
  );

  // ── Monitoring ───────────────────────────────────────────────────────────

}
