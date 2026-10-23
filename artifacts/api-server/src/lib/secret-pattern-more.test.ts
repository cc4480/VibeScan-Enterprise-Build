import { describe, it, expect } from "vitest";
import { SECRET_PATTERNS } from "./secret-pattern-data";
import { scanContent } from "./jsScanner";

/**
 * Each vendor format: a token of the right shape, a near miss that must not match, and the scanner as a whole
 * reporting it. Tokens are built here from a deterministic generator so the repository holds no real-looking credential.
 */
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HEX = "0123456789abcdef";
const LOWER = "abcdefghijklmnopqrstuvwxyz0123456789";
const URLSAFE = `${ALNUM}_-`;
const B64 = `${ALNUM}+/`;
const DIGITS = "0123456789";

let seed = 20261014;
function rnd(n: number, alphabet: string): string {
  let out = "";
  for (let i = 0; i < n; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
    out += alphabet[(seed >> 8) % alphabet.length];
  }
  return out;
}

interface Case { name: string; token: () => string; nearMiss: () => string; before?: string }

const cases: Case[] = [
  { name: "Groq API Key Exposed", token: () => `gsk_${rnd(52, ALNUM)}`, nearMiss: () => `gsk_${rnd(20, ALNUM)}` },
  { name: "OpenRouter API Key Exposed", token: () => `sk-or-v1-${rnd(64, HEX)}`, nearMiss: () => `sk-or-v1-${rnd(40, HEX)}` },
  { name: "xAI API Key Exposed", token: () => `xai-${rnd(80, ALNUM)}`, nearMiss: () => `xai-${rnd(30, ALNUM)}` },
  { name: "Perplexity API Key Exposed", token: () => `pplx-${rnd(48, ALNUM)}`, nearMiss: () => `pplx-${rnd(20, ALNUM)}` },
  { name: "Together AI API Key Exposed", token: () => `tgp_v1_${rnd(43, URLSAFE)}`, nearMiss: () => `tgp_v1_${rnd(10, URLSAFE)}` },
  { name: "Hugging Face Access Token Exposed", token: () => `hf_${rnd(34, ALPHA)}`, nearMiss: () => `hf_${rnd(12, ALPHA)}` },
  { name: "Pinecone API Key Exposed", token: () => `pcsk_${rnd(56, `${ALNUM}_`)}`, nearMiss: () => `pcsk_${rnd(12, ALNUM)}` },
  { name: "npm Access Token Exposed", token: () => `npm_${rnd(36, ALNUM)}`, nearMiss: () => `npm_${rnd(12, ALNUM)}` },
  { name: "PyPI API Token Exposed", token: () => `pypi-AgEIcHlwaS5vcmc${rnd(70, URLSAFE)}`, nearMiss: () => `pypi-AgEIcHlwaS5vcmc${rnd(10, URLSAFE)}` },
  { name: "DigitalOcean Token Exposed", token: () => `dop_v1_${rnd(64, HEX)}`, nearMiss: () => `dop_v1_${rnd(20, HEX)}` },
  { name: "PlanetScale Credential Exposed", token: () => `pscale_tkn_${rnd(43, URLSAFE)}`, nearMiss: () => `pscale_tkn_${rnd(8, URLSAFE)}` },
  { name: "Doppler Token Exposed", token: () => `dp.pt.${rnd(43, ALNUM)}`, nearMiss: () => `dp.pt.${rnd(10, ALNUM)}` },
  { name: "Pulumi Access Token Exposed", token: () => `pul-${rnd(40, HEX)}`, nearMiss: () => `pul-${rnd(12, HEX)}` },
  { name: "Neon API Key Exposed", token: () => `napi_${rnd(64, LOWER)}`, nearMiss: () => `napi_${rnd(12, LOWER)}` },
  { name: "Supabase Management Token Exposed", token: () => `sbp_${rnd(40, HEX)}`, nearMiss: () => `sbp_${rnd(12, HEX)}` },
  { name: "Databricks Access Token Exposed", token: () => `dapi${rnd(32, HEX)}`, nearMiss: () => `dapi${rnd(10, HEX)}` },
  { name: "Netlify Personal Access Token Exposed", token: () => `nfp_${rnd(36, ALNUM)}`, nearMiss: () => `nfp_${rnd(10, ALNUM)}` },
  { name: "Atlassian API Token Exposed", token: () => `ATATT3${rnd(170, `${URLSAFE}=`)}`, nearMiss: () => `ATATT3${rnd(20, URLSAFE)}` },
  { name: "Linear API Key Exposed", token: () => `lin_api_${rnd(40, ALNUM)}`, nearMiss: () => `lin_api_${rnd(10, ALNUM)}` },
  { name: "Notion Integration Token Exposed", token: () => `ntn_${rnd(44, ALNUM)}`, nearMiss: () => `ntn_${rnd(10, ALNUM)}` },
  { name: "Figma Access Token Exposed", token: () => `figd_${rnd(44, URLSAFE)}`, nearMiss: () => `figd_${rnd(10, URLSAFE)}` },
  { name: "Shopify Access Token Exposed", token: () => `shpat_${rnd(32, HEX)}`, nearMiss: () => `shpat_${rnd(10, HEX)}` },
  { name: "Square Credential Exposed", token: () => `sq0atp-${rnd(22, URLSAFE)}`, nearMiss: () => `sq0atp-${rnd(6, URLSAFE)}` },
  { name: "Brevo (Sendinblue) API Key Exposed", token: () => `xkeysib-${rnd(64, HEX)}-${rnd(16, ALNUM)}`, nearMiss: () => `xkeysib-${rnd(20, HEX)}` },
  { name: "Telegram Bot Token Exposed", token: () => `${rnd(9, DIGITS)}:AA${rnd(33, URLSAFE)}`, nearMiss: () => `${rnd(9, DIGITS)}:AA${rnd(8, URLSAFE)}` },
  { name: "Discord Bot Token Exposed", token: () => `M${rnd(23, URLSAFE)}.${rnd(6, URLSAFE)}.${rnd(30, URLSAFE)}`, nearMiss: () => `M${rnd(10, URLSAFE)}.${rnd(6, URLSAFE)}.${rnd(10, URLSAFE)}`, before: 'const discordToken = "' },
  { name: "Mailgun API Key Exposed", token: () => `key-${rnd(32, HEX)}`, nearMiss: () => `key-${rnd(10, HEX)}`, before: 'const mailgunKey = "' },
  {
    name: "Azure Storage Account Key Exposed",
    token: () => `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${rnd(86, B64)}==;EndpointSuffix=core.windows.net`,
    nearMiss: () => `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${rnd(20, B64)}==`,
  },
  {
    name: "Google Cloud Service Account Key Exposed",
    token: () => `{"type": "service_account", "project_id": "demo", "private_key_id": "${rnd(40, HEX)}", "private_key": "x"}`,
    nearMiss: () => `{"type": "service_account", "project_id": "demo", "private_key_id": "${rnd(8, HEX)}"}`,
  },
];

describe("vendor secret formats", () => {
  for (const c of cases) {
    describe(c.name, () => {
      const entry = SECRET_PATTERNS.find((p) => p.name === c.name);

      it("exists, with a severity, a CWE and advice to revoke", () => {
        expect(entry).toBeDefined();
        expect(entry!.cweId).toBe("CWE-798");
        expect(entry!.solution).toMatch(/revoke/i);
      });

      it("matches a token of the right shape", () => {
        expect(entry!.pattern.test(`${c.before ?? ""}${c.token()}`)).toBe(true);
      });

      it("does not match a near miss", () => {
        expect(entry!.pattern.test(`${c.before ?? ""}${c.nearMiss()}`)).toBe(false);
      });

      it("is reported by the scanner, and not hidden by the placeholder filter", () => {
        const text = c.before ? `${c.before}${c.token()}";` : `const value = "${c.token()}";`;
        expect(scanContent(text).map((h) => h.pattern.name)).toContain(c.name);
      });
    });
  }
});

describe("vendor secret formats stay quiet on ordinary code", () => {
  const ordinary = [
    "const npm_config_registry = process.env.npm_config_registry;",
    "from huggingface_hub import hf_hub_download",
    "const key = 'sk-or-v1-';",
    "className='dp.pt.inline-block'",
    "const discordToken = process.env.DISCORD_TOKEN;",
    "// the napi_ prefix is used by Neon",
    "id: 'dapi'",
    "AccountKey=<your-account-key>",
    "telegram: 123456789:AA",
  ];
  for (const line of ordinary) {
    it(`finds nothing in: ${line}`, () => {
      const moreNames = new Set(cases.map((c) => c.name));
      expect(scanContent(line).filter((h) => moreNames.has(h.pattern.name))).toEqual([]);
    });
  }

  it("does not report a bare Discord- or Mailgun-shaped value without its context word", () => {
    const discord = SECRET_PATTERNS.find((p) => p.name === "Discord Bot Token Exposed")!;
    const mailgun = SECRET_PATTERNS.find((p) => p.name === "Mailgun API Key Exposed")!;
    expect(discord.pattern.test(`M${rnd(23, URLSAFE)}.${rnd(6, URLSAFE)}.${rnd(30, URLSAFE)}`)).toBe(false);
    expect(mailgun.pattern.test(`key-${rnd(32, HEX)}`)).toBe(false);
  });
});
