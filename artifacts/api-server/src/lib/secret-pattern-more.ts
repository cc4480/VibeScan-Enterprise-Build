/**
 * Data module: secret patterns for AI, developer-infrastructure, payment and messaging vendors that vibe-coded apps
 * commonly leak. Every pattern here is a vendor's own token format: a distinctive prefix and a fixed shape, so a match
 * is the vendor's credential and not a word that happens to look like one. Where a format has no distinctive prefix
 * (Discord, Mailgun), the match must also follow a word that names the vendor or a token, as the Resend pattern does.
 *
 * Formats are from the vendors' own documentation and from the public detector lists of GitHub secret scanning,
 * TruffleHog and Gitleaks. A pattern is only added when the shape is well attested: a wrong guess here turns into a
 * false "critical" on a stranger's page.
 */
import type { SecretPattern } from "./secret-pattern-data";

type Severity = SecretPattern["severity"];

function vendor(o: {
  name: string;
  pattern: RegExp;
  severity: Severity;
  cvss: number;
  /** What the credential lets a stranger do, in a sentence. */
  grants: string;
  /** Where to revoke it. */
  revoke: string;
}): SecretPattern {
  return {
    name: o.name,
    pattern: o.pattern,
    severity: o.severity,
    cvssScore: o.cvss,
    cweId: "CWE-798",
    description: `${o.name.replace(/ Exposed$/, "")} credential found in client-side code or a repository. ${o.grants} Anyone who can read the page or the repository can copy it.`,
    solution: `Revoke it now (${o.revoke}) and create a replacement. Keep the new one in a server-side environment variable or secrets manager, never in frontend code or a committed file; deleting it from the code does not remove it from Git history or from bundles already served.`,
  };
}

export const MORE_VENDOR_PATTERNS: SecretPattern[] = [
  // ── AI providers ─────────────────────────────────────────────────────────────────────────────────────────────────
  vendor({ name: "Groq API Key Exposed", pattern: /\bgsk_[A-Za-z0-9]{52}\b/, severity: "high", cvss: 8.1, grants: "It allows calls to Groq-hosted models billed to the account.", revoke: "console.groq.com/keys" }),
  vendor({ name: "OpenRouter API Key Exposed", pattern: /\bsk-or-v1-[a-f0-9]{64}\b/, severity: "high", cvss: 8.1, grants: "It allows calls to any model OpenRouter serves, billed to the account's credits.", revoke: "openrouter.ai/keys" }),
  vendor({ name: "xAI API Key Exposed", pattern: /\bxai-[A-Za-z0-9]{80}\b/, severity: "high", cvss: 8.1, grants: "It allows calls to xAI models billed to the account.", revoke: "console.x.ai" }),
  vendor({ name: "Perplexity API Key Exposed", pattern: /\bpplx-[A-Za-z0-9]{48}\b/, severity: "high", cvss: 8.1, grants: "It allows Perplexity API calls billed to the account.", revoke: "perplexity.ai/settings/api" }),
  vendor({ name: "Together AI API Key Exposed", pattern: /\btgp_v1_[A-Za-z0-9_-]{43}\b/, severity: "high", cvss: 8.1, grants: "It allows calls to Together AI models billed to the account.", revoke: "api.together.ai/settings/api-keys" }),
  vendor({ name: "Hugging Face Access Token Exposed", pattern: /\bhf_[A-Za-z]{34}\b/, severity: "high", cvss: 8.1, grants: "It can read the account's private models and datasets and, with a write token, change or delete them.", revoke: "huggingface.co/settings/tokens" }),
  vendor({ name: "Pinecone API Key Exposed", pattern: /\bpcsk_[A-Za-z0-9_]{50,}\b/, severity: "high", cvss: 8.1, grants: "It gives read and write access to the account's vector indexes.", revoke: "app.pinecone.io" }),

  // ── Developer infrastructure ────────────────────────────────────────────────────────────────────────────────────
  vendor({ name: "npm Access Token Exposed", pattern: /\bnpm_[A-Za-z0-9]{36}\b/, severity: "critical", cvss: 9.1, grants: "A token with publish rights lets an attacker push a malicious version of your packages to everyone who installs them.", revoke: "npmjs.com > Access Tokens" }),
  vendor({ name: "PyPI API Token Exposed", pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/, severity: "critical", cvss: 9.1, grants: "It allows publishing releases of your Python packages to everyone who installs them.", revoke: "pypi.org/manage/account/token" }),
  vendor({ name: "DigitalOcean Token Exposed", pattern: /\bdo[opr]_v1_[a-f0-9]{64}\b/, severity: "critical", cvss: 9.1, grants: "It gives access to the account's servers, databases and storage through the DigitalOcean API.", revoke: "cloud.digitalocean.com/account/api" }),
  vendor({ name: "PlanetScale Credential Exposed", pattern: /\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_-]{32,64}\b/, severity: "critical", cvss: 9.1, grants: "It gives access to the database or to the PlanetScale account.", revoke: "app.planetscale.com > Settings" }),
  vendor({ name: "Doppler Token Exposed", pattern: /\bdp\.pt\.[A-Za-z0-9]{43}\b/, severity: "critical", cvss: 9.1, grants: "It reads every secret in the Doppler project it belongs to.", revoke: "dashboard.doppler.com > Access" }),
  vendor({ name: "Pulumi Access Token Exposed", pattern: /\bpul-[a-f0-9]{40}\b/, severity: "high", cvss: 8.1, grants: "It allows reading and changing the account's infrastructure stacks and their secrets.", revoke: "app.pulumi.com/account/tokens" }),
  vendor({ name: "Neon API Key Exposed", pattern: /\bnapi_[a-z0-9]{60,}\b/, severity: "high", cvss: 8.1, grants: "It manages the account's Neon Postgres projects and databases.", revoke: "console.neon.tech > Account settings > API keys" }),
  vendor({ name: "Supabase Management Token Exposed", pattern: /\bsbp_[a-f0-9]{40}\b/, severity: "critical", cvss: 9.1, grants: "A personal access token manages every Supabase project of the account, including its database keys.", revoke: "supabase.com/dashboard/account/tokens" }),
  vendor({ name: "Databricks Access Token Exposed", pattern: /\bdapi[a-f0-9]{32}\b/, severity: "high", cvss: 8.1, grants: "It gives access to the Databricks workspace as the user who created it.", revoke: "the workspace's User Settings > Developer" }),
  vendor({ name: "Netlify Personal Access Token Exposed", pattern: /\bnfp_[A-Za-z0-9]{36}\b/, severity: "high", cvss: 8.1, grants: "It can deploy to, and read the settings and environment variables of, the account's sites.", revoke: "app.netlify.com/user/applications" }),
  vendor({ name: "Atlassian API Token Exposed", pattern: /\bATATT3[A-Za-z0-9_\-=]{150,}/, severity: "high", cvss: 8.1, grants: "It acts as the user in Jira, Confluence and Bitbucket Cloud.", revoke: "id.atlassian.com/manage-profile/security/api-tokens" }),
  vendor({ name: "Linear API Key Exposed", pattern: /\blin_api_[A-Za-z0-9]{40}\b/, severity: "high", cvss: 7.5, grants: "It reads and writes the workspace's issues and projects as the user.", revoke: "linear.app > Settings > API" }),
  vendor({ name: "Notion Integration Token Exposed", pattern: /\bntn_[A-Za-z0-9]{40,60}\b/, severity: "high", cvss: 7.5, grants: "It reads and edits every page shared with the integration.", revoke: "notion.so/profile/integrations" }),
  vendor({ name: "Figma Access Token Exposed", pattern: /\bfigd_[A-Za-z0-9_-]{40,}\b/, severity: "medium", cvss: 6.5, grants: "It reads the account's design files.", revoke: "figma.com > Settings > Security" }),

  // ── Payments and commerce ───────────────────────────────────────────────────────────────────────────────────────
  vendor({ name: "Shopify Access Token Exposed", pattern: /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/, severity: "high", cvss: 8.1, grants: "It reads and changes the store's orders, customers and products, as far as the app's permissions reach.", revoke: "the store admin > Apps" }),
  vendor({ name: "Square Credential Exposed", pattern: /\b(?:sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}|EAAA[A-Za-z0-9_-]{60})\b/, severity: "critical", cvss: 9.1, grants: "It can take payments, issue refunds and read the account's customers and transactions.", revoke: "developer.squareup.com/apps" }),

  // ── Email and messaging ─────────────────────────────────────────────────────────────────────────────────────────
  vendor({ name: "Brevo (Sendinblue) API Key Exposed", pattern: /\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b/, severity: "high", cvss: 8.1, grants: "It sends email as your domain and reads the account's contacts.", revoke: "app.brevo.com/settings/keys/api" }),
  vendor({ name: "Telegram Bot Token Exposed", pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/, severity: "high", cvss: 7.5, grants: "It controls the bot: reading its messages and sending as it.", revoke: "@BotFather > /revoke" }),
  {
    ...vendor({ name: "Discord Bot Token Exposed", pattern: /(?<=(?:discord|bot[_-]?token|token)[^\n]{0,40})\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b/i, severity: "high", cvss: 8.1, grants: "It controls the bot in every server it has joined.", revoke: "discord.com/developers/applications > Bot > Reset Token" }),
  },
  vendor({
    name: "Mailgun API Key Exposed",
    pattern: /(?<=mailgun[^\n]{0,40})\b(?:key-[a-f0-9]{32}|[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\b/i,
    severity: "high", cvss: 8.1, grants: "It sends email as your domain and reads the account's logs and recipients.", revoke: "app.mailgun.com > API security",
  }),

  // ── Cloud credentials in a file ─────────────────────────────────────────────────────────────────────────────────
  vendor({
    name: "Azure Storage Account Key Exposed",
    pattern: /DefaultEndpointsProtocol=https?;[^\n"'`]{0,200}?AccountKey=[A-Za-z0-9+/]{86}==/,
    severity: "critical", cvss: 9.1, grants: "The account key is full control of every container, blob, queue and table in the storage account.", revoke: "portal.azure.com > the storage account > Access keys > Rotate",
  }),
  {
    ...vendor({
      name: "Google Cloud Service Account Key Exposed",
      pattern: /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key_id"\s*:\s*"[a-f0-9]{40}"/,
      severity: "critical", cvss: 9.8, grants: "A service account key file acts as that service account, with every permission it has been given.", revoke: "console.cloud.google.com > IAM > Service accounts > Keys",
    }),
    // The key file is JSON, and a JSON key file is not a "placeholder token" by its shape.
    skipPlaceholderCheck: true,
  },
];
