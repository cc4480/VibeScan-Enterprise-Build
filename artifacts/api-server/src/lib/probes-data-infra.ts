import type { SensitivePath } from "./probes-data";

/** Dependency lockfiles, cloud and infrastructure secrets, and database admin panels. */
export const SENSITIVE_PATHS_INFRA: SensitivePath[] = [
  // ── Dependency lockfiles ───────────────────────────────────────────────────
  {
    path: "/yarn.lock",
    name: "yarn.lock Dependency Lockfile Exposed",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "yarn.lock is publicly accessible, revealing the exact version of every package in the dependency tree. Attackers cross-reference these versions against CVE databases to identify exploitable packages with precision, skipping the fingerprinting step entirely.",
    solution: "Block lockfiles at the web server. They should not be placed in the web root.",
    validate: (body) => /^# yarn lockfile|^# This file is generated/m.test(body) || (/resolved "https:\/\/registry/m.test(body) && body.length > 200),
  },
  {
    path: "/package-lock.json",
    name: "npm package-lock.json Exposed",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "package-lock.json is accessible, providing the complete resolved dependency tree with exact versions. This is a precision CVE-targeting blueprint.",
    solution: "Block lockfiles at the web server.",
    validate: (body, ct) => (ct.includes("json") || body.trim().startsWith("{")) && /"lockfileVersion"|"packages"|"dependencies"/.test(body),
  },
  {
    path: "/composer.lock",
    name: "PHP composer.lock Exposed",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "composer.lock is accessible, revealing all PHP package versions in use. Attackers use this to target known vulnerabilities in specific package versions.",
    solution: "Block composer.lock at the web server.",
    validate: (body) => /"content-hash"|"packages"|"platform"/i.test(body),
  },
  {
    path: "/Gemfile.lock",
    name: "Ruby Gemfile.lock Exposed",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "Gemfile.lock is publicly accessible, exposing all Ruby gem versions and dependency sources.",
    solution: "Block Gemfile.lock at the web server.",
    validate: (body) => /GEM\s+remote:|BUNDLED WITH|PLATFORMS/m.test(body),
  },
  {
    path: "/Pipfile.lock",
    name: "Python Pipfile.lock Exposed",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "Pipfile.lock is accessible, revealing all Python package versions. Useful for identifying vulnerable dependencies.",
    solution: "Block Pipfile.lock at the web server.",
    validate: (body) => /"_meta"|"default"|"develop"/.test(body) && /"version":/.test(body),
  },
  {
    path: "/requirements.txt",
    name: "Python requirements.txt Exposed",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "requirements.txt is publicly accessible, listing all Python dependencies and their pinned versions.",
    solution: "Block requirements.txt at the web server.",
    validate: (body) => /^[a-zA-Z][\w.-]*(==|>=|<=|~=|!=|>|<)\d/m.test(body) || (/^[a-zA-Z][\w.-]+$/m.test(body) && body.split("\n").length > 3),
  },

  // ── Cloud / infrastructure secrets ────────────────────────────────────────
  {
    path: "/terraform.tfstate",
    name: "Terraform State File Exposed — Infrastructure Secrets",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "A Terraform state file is publicly accessible. Terraform state files contain a complete inventory of your cloud infrastructure in plaintext, including resource IDs, database connection strings, API keys, access tokens, private IPs, and any secrets passed as Terraform variables or outputs. This is one of the most sensitive files in any infrastructure.",
    solution: "Remove terraform.tfstate from the web server immediately. Store Terraform state in a remote backend with encryption and access controls (Terraform Cloud, S3 with SSE, GCS). Never commit state files to repositories or deploy them to web servers.",
    validate: (body) => /"terraform_version"|"resources"|"outputs"/.test(body.slice(0, 2000)),
  },
  {
    path: "/.aws/credentials",
    name: "AWS Credentials File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "An AWS credentials file is publicly accessible. This file contains AWS Access Key IDs and Secret Access Keys in plaintext, granting API-level access to all AWS services the associated user or role can access.",
    solution: "Remove .aws/credentials from the web server immediately. Rotate all exposed credentials in the AWS IAM console. Use IAM roles for EC2/Lambda instead of static credentials files.",
    validate: (body) => /\[default\]|aws_access_key_id|aws_secret_access_key/i.test(body),
  },
  {
    path: "/.kube/config",
    name: "Kubernetes Config File Exposed — Cluster Credentials",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "A Kubernetes kubeconfig file is publicly accessible. This file contains cluster API server addresses, client certificates or tokens, and namespace context — providing full kubectl access to the Kubernetes cluster.",
    solution: "Remove .kube/config from the web server immediately. Rotate all cluster credentials. Never deploy kubeconfig files to web servers.",
    validate: (body) => /apiVersion:|clusters:|users:|contexts:|kind: Config/i.test(body),
  },
  {
    path: "/id_rsa",
    name: "SSH Private Key Exposed (id_rsa)",
    severity: "critical", cweId: "CWE-312", cvssScore: 10.0,
    category: "Credential Exposure",
    description: "An SSH private key file is publicly accessible. Anyone who downloads this file can authenticate as the key's owner to any server that has the corresponding public key authorized. This typically grants root or admin shell access.",
    solution: "Remove id_rsa from the web server immediately and consider it completely compromised. Generate a new key pair, deploy the new public key to all servers, and revoke the old public key from all authorized_keys files.",
    validate: (body) => /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(body),
  },
  {
    path: "/.ssh/id_rsa",
    name: "SSH Private Key Exposed (.ssh/id_rsa)",
    severity: "critical", cweId: "CWE-312", cvssScore: 10.0,
    category: "Credential Exposure",
    description: "An SSH private key is publicly accessible at .ssh/id_rsa. Anyone downloading this file can authenticate as the key owner to all servers that trust this key.",
    solution: "Remove the key from the web server, revoke it from all authorized_keys files, and generate a new key pair.",
    validate: (body) => /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(body),
  },
  {
    path: "/.bash_history",
    name: "Bash History File Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: ".bash_history is publicly accessible. Shell history files contain previously executed commands including curl requests with auth tokens, database connection strings typed directly, passwords passed as command-line arguments, and internal server addresses.",
    solution: "Remove .bash_history from the web root. Block dotfiles at the web server: `location ~ /\\. { deny all; }`",
    validate: (body) => body.length > 50 && /\b(sudo|curl|wget|mysql|psql|ssh|scp|git|npm|docker|kubectl)\b/i.test(body),
  },

  // ── Database admin panels ─────────────────────────────────────────────────
  {
    path: "/phpmyadmin/",
    servesHtml: true,
    name: "phpMyAdmin Database Admin Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 8.1,
    category: "Information Disclosure",
    description: "A phpMyAdmin database administration interface is accessible. If default or weak credentials are used, attackers gain full database access including reading all data, exfiltrating user credentials, modifying records, and executing SQL to write webshells.",
    solution: "Restrict phpMyAdmin to localhost or VPN-only access. Enable authentication with a strong password. Ideally, remove it from the production server entirely and use a secure tunnel for DB access.",
    // Require an actual login-form/interface marker, not just the word
    // "phpMyAdmin" appearing in the page — that alone also matches unrelated
    // pages that merely mention the project by name (e.g. a GitHub org page
    // for the real phpMyAdmin project).
    validate: (body) =>
      /name=["']pma_username["']|name=["']pma_password["']|id=["']pma_navigation["']|pmaHomepage|pma_absolute_uri/i.test(body),
  },
  {
    path: "/adminer.php",
    servesHtml: true,
    name: "Adminer Database Admin Tool Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 8.1,
    category: "Information Disclosure",
    description: "Adminer (formerly phpMinAdmin) is publicly accessible. This single-file database admin tool gives attackers a GUI to connect to any database server visible from the web server, not just the local database.",
    solution: "Remove adminer.php from production immediately. For development use only — restrict with IP allowlisting if kept on staging servers.",
    // Require Adminer's actual login-form field names or footer credit link,
    // not just the word "adminer" appearing anywhere in the page.
    validate: (body) =>
      /name=["']auth\[(driver|server|username|password)\]["']|href=["'][^"']*adminer\.org/i.test(body),
  },

];
