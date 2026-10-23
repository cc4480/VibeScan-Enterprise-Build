import { hostStackNotes, type HostEnvironment } from "./deepseekPromptsHosts";

export type AgentEnvironment = "lovable" | "nextjs" | "bolt" | "wordpress" | "supabase" | HostEnvironment | "generic";

/**
 * What the model is told about the fix prompt it writes.
 *
 * There is ONE prompt for every tool. A report cannot know which assistant the reader will paste it
 * into (Claude Code, Cursor, Codex, GitHub Copilot, Windsurf, Grok Build, Gemini, ChatGPT, or an app
 * builder such as Lovable, Bolt, Replit or v0), and the reader may use several. So the prompt names no
 * tool and uses no tool's commands, modes or @-mentions. What the scan can tell about the site's stack
 * goes in as STACK NOTES: facts about where fixes live on that platform, useful to any tool.
 */
export function agentPromptInstructions(agent: AgentEnvironment, domain: string): string {
  return `FIX PROMPT: ONE universal prompt, pasted unchanged into whichever AI coding tool the reader uses (Claude Code, Cursor, Codex, GitHub Copilot, Windsurf, Grok Build, Gemini, ChatGPT, or an app builder such as Lovable, Bolt, Replit or v0). You do not know which.

Rules for agentFixPrompt:
- Tool-neutral: never name an AI tool, and never use a tool's own commands, slash commands, @-mentions, mode names or UI steps
- Self-contained, plain text with markdown headings, not wrapped in a code fence. It must make sense with no other context
- Open with: "I ran an automated security scan on ${domain} and found the issues below. Please fix them in this project's codebase. If you cannot read or edit files here, give me the exact change to make for each issue instead."
- One section per finding: a heading "### <number>. <Finding name> (<SEVERITY>)", then four labelled lines, each starting a new line: "Problem:" (one sentence), "Fix:" (the exact change: code, config lines or a setting), "Where to look:" (what to search for and which kind of file; call a file name likely, never invent a path) and "Check:" (one way to confirm it is fixed, such as a header to look for or a request that should now fail)
- Every section has all four labels, with no exceptions. With more than 8 findings, merge closely related ones into one section (name each finding in it) so there are never more than 8 sections; shorten the wording, never drop a label
- Most severe first. An exposed secret is always first, and the instruction is to rotate it as well as remove it
- Ask for the smallest change that fixes each issue, to search the whole project for the same insecure pattern and fix every place, to leave unrelated code alone, and to add a package only if a fix needs one
- If a finding does not apply to how the project is built, tell the assistant to say so rather than guess
- Close with: "When you are done, list each file you changed and what you changed, anything you could not fix and why, and run the project's build or tests if it has them."
- Keep under 4500 characters

STACK NOTES (facts about this site's stack, for the assistant; leave out any that do not help with a finding):
${stackNotes(agent)}`;
}

function stackNotes(agent: AgentEnvironment): string {
  switch (agent) {
    case "lovable":
    case "bolt":
      return `Built with a chat-based app builder.
- Describe each change in plain terms as well as in code; the builder applies changes through its chat and settings
- For Supabase issues include the dashboard path, for example Table Editor, choose the table, Enable RLS
- For headers or cookies, say what setting to add and where in the server or host settings`;

    case "nextjs":
      return `Next.js project.
- Security headers go in next.config (headers()) or middleware.ts; route handlers live under app/api or pages/api
- Name the exact file to edit and show before and after code where it helps; include install commands only if a new package is needed`;

    case "wordpress":
      return `WordPress site.
- Fixes use plugins, wp-config.php, .htaccess or Admin Panel settings; prefer a named plugin or setting over raw PHP where one exists
- Give Admin Panel paths, for example Settings, General`;

    case "supabase":
      return `Supabase backend.
- Group fixes into three labeled parts: "SQL to run in the Supabase SQL Editor" (exact CREATE POLICY and ALTER TABLE ... ENABLE ROW LEVEL SECURITY statements), "Supabase Dashboard changes" (navigation paths and toggles), "Code changes" (environment variables and client setup)
- The anon key is meant to be public; the protection is Row Level Security, and the service_role key must never reach client code`;

    case "vercel":
    case "netlify":
    case "firebase":
    case "hosted":
      return hostStackNotes(agent);

    case "generic":
    default:
      return "No specific stack was detected; use each finding's own remediation.";
  }
}
