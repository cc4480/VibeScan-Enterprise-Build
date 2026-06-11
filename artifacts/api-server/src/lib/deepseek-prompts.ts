export type AgentEnvironment = "lovable" | "nextjs" | "bolt" | "wordpress" | "supabase" | "generic";

export function agentPromptInstructions(agent: AgentEnvironment, domain: string): string {
  switch (agent) {
    case "lovable":
      return `AGENT TARGET: Lovable (AI web app builder — https://lovable.dev)
The user built this app with Lovable. Generate the agentFixPrompt as a Lovable chat message the user pastes directly into the Lovable chat interface.

Rules for agentFixPrompt:
- Open with: "Please fix these security issues in my app:"
- Write conversationally — Lovable understands natural language, not file paths
- DO NOT reference file paths; describe what needs to change in plain English
- For Supabase issues: include Supabase dashboard instructions (e.g. "In the Supabase dashboard → Table Editor → [table], click 'Enable RLS'")
- For header/cookie fixes: say what setting to add, e.g. "Add a Content-Security-Policy header in the server settings"
- Close with: "Apply all of these fixes and tell me what you changed."
- Keep under 2000 characters`;

    case "nextjs":
      return `AGENT TARGET: Cursor or Claude Code (IDE AI agent with full file access on a Next.js project)
The site runs Next.js — the developer likely uses Cursor Composer, Claude Code, or GitHub Copilot.

Rules for agentFixPrompt:
- Open with: "I ran a security scan on ${domain} and found these issues. Please fix them in my Next.js codebase."
- For each finding: specify the exact file to edit (e.g. \`middleware.ts\`, \`next.config.ts\`, \`app/api/route.ts\`)
- Show exact code snippets — before/after blocks where helpful
- Include npm/pnpm install commands if new packages are needed
- Reference Next.js-specific APIs: middleware for security headers, next.config for rewrites, app/api/ for route handlers
- Close with: "Show me the exact code change for each file."`;

    case "bolt":
      return `AGENT TARGET: Bolt.new or Replit Agent (full-file editing agent)
The site was built with Bolt.new or a similar full-file editing environment.

Rules for agentFixPrompt:
- Open with: "Fix these security issues in my app:"
- For each finding: specify the full file path and describe the complete change
- Prefer complete file content over partial diffs — Bolt.new works best with full files
- Include package.json dependency additions if new packages are needed
- Use clear file headers: "=== FILE: src/lib/auth.ts ==="
- Close with: "Make all of these changes. Show me each complete updated file."`;

    case "wordpress":
      return `AGENT TARGET: WordPress (CMS platform)
The site runs WordPress — fixes should use plugins, wp-config.php, or .htaccess.

Rules for agentFixPrompt:
- Open with: "Fix these security issues on my WordPress site:"
- For each finding: give WordPress-specific remediation (plugin name to install, wp-config.php line to add, .htaccess rule, or Admin Panel path)
- Prefer plugin solutions: e.g. "Install Wordfence Security and configure..." rather than raw PHP code
- Reference Admin Panel paths: e.g. "Settings → General", "Users → Your Profile"
- Close with: "Implement all of these WordPress security hardening steps."`;

    case "supabase":
      return `AGENT TARGET: Supabase (Backend-as-a-Service)
The app uses Supabase. Structure fixes as SQL + dashboard instructions + code changes.

Rules for agentFixPrompt:
- Open with: "Fix these security issues in my Supabase app:"
- Group fixes into three labeled sections:
  1. "SQL to run in Supabase SQL Editor:" — exact CREATE POLICY, ALTER TABLE, ENABLE ROW LEVEL SECURITY statements
  2. "Supabase Dashboard changes:" — specific navigation paths and toggle settings
  3. "Code changes:" — environment variable and client initialization fixes
- Close with: "Apply all SQL policies, change the dashboard settings, and update the code."`;

    case "generic":
    default:
      return `AGENT TARGET: Generic AI coding agent (Cursor, Claude, GitHub Copilot)

Rules for agentFixPrompt:
- Open with: "I ran a penetration test on ${domain} and found the following security issues that need to be fixed in my codebase."
- For each finding use a markdown heading like "### 1. <Finding Name> (<SEVERITY>)" followed by a one-sentence description and the exact remediation to implement
- Close with: "Please fix all of the above issues in my codebase. For each fix, show me the exact code change."
- Use plain text with markdown headings only — do not wrap in a code fence
- Keep under 3000 characters`;
  }
}
