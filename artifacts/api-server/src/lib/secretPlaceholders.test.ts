import { describe, it, expect } from "vitest";
import { scanContent } from "./jsScanner";
import { looksLikeAName, looksLikeReference, isPlaceholderToken } from "./secretPlaceholders";

/**
 * Placeholders and example values reported as live secrets. Every case below was reproduced by
 * running the repo's own pattern data; they matter most in the files the GitHub source scan
 * deliberately reads (.env.example is a candidate path, twice), where placeholders are the norm.
 */
const names = (content: string): string[] => scanContent(content).map((f) => f.pattern.name);
const x = (n: number) => "x".repeat(n);

describe("fixed-format tokens filled with filler are not secrets", () => {
  it.each([
    ["Stripe live key", `STRIPE_SECRET_KEY=sk_live_${x(24)}`],
    ["GitHub PAT", `GITHUB_TOKEN=ghp_${x(36)}`],
    ["OpenAI project key", `OPENAI_API_KEY=sk-proj-${x(60)}`],
    ["Anthropic key", `ANTHROPIC_API_KEY=sk-ant-api03-${x(95)}`],
    ["SendGrid key", `SENDGRID_API_KEY=SG.${x(22)}.${x(43)}`],
    ["Sentry legacy token", `sentry_token: "${"a".repeat(64)}"`],
    ["Slack webhook", `SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/${"X".repeat(24)}`],
    ["Stripe test key from Stripe's own docs", "STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc"],
    ["AWS key from AWS's own docs", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"],
    ["a run of zeros", `STRIPE_SECRET_KEY=sk_live_${"0".repeat(24)}`],
  ])("%s", (_label, content) => {
    expect(names(content)).toEqual([]);
  });

  it.each([
    ["a Stripe live key", "STRIPE_SECRET_KEY=sk_live_51JvQ8rKx2Lw9ZpTn4Uc7YhBa3DfGm"],
    ["a GitHub PAT", "GITHUB_TOKEN=ghp_R8x2KqL9mVb3ZtN7yHc4WdF6sJpA1eUoXgQi"],
    ["an OpenAI project key", `OPENAI_API_KEY=sk-proj-${"Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0UoYgFi".repeat(2)}`],
    ["an AWS key id", "AWS_ACCESS_KEY_ID=AKIAQZPXMC4278HDVBNR"],
  ])("still reports %s", (_label, content) => {
    expect(names(content).length).toBeGreaterThan(0);
  });
});

describe("database URLs that only reach the developer's own machine are not exposed credentials", () => {
  it.each([
    "DATABASE_URL=postgres://postgres:postgres@localhost:5432/mydb",
    "MONGO_URL=mongodb://admin:admin123@localhost:27017/db",
    "DATABASE_URL=mysql://root:toor1234@db:3306/app",
    "DATABASE_URL=postgres://app:app@127.0.0.1:5432/app",
    "DATABASE_URL=postgres://user:user@host.docker.internal:5432/app",
  ])("%s", (content) => {
    expect(names(content)).toEqual([]);
  });

  it("still reports a database URL with a real password on a real host", () => {
    expect(names("DATABASE_URL=postgres://app_user:Qm7vZk2Rt9LxWc4B@db.prod.acme-internal.io:5432/app")).toContain(
      "Database Connection URL with Credentials Exposed",
    );
  });

  it("still reports a real password on a docker service host name, where the password is not a default", () => {
    expect(names("DATABASE_URL=postgres://app:Vt8Hq3ZmLk2Rw9Xc@db:5432/app")).toContain(
      "Database Connection URL with Credentials Exposed",
    );
  });
});

describe("frontend-bundle env vars: a name or a reference is not the secret", () => {
  const vite = (key: string, value: string) => `{ "${key}": "${value}" }`;
  it.each([
    ["VITE_DEEPSEEK_API_KEY", "MY_DEEPSEEK_API_KEY"],
    ["VITE_STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY_HERE_REPLACE"],
    ["VITE_AUTH_TOKEN", "your-auth-token-goes-here"],
    ["VITE_API_TOKEN", "process.env.API_TOKEN_VALUE"],
    ["VITE_API_KEY", "${VITE_API_KEY_VALUE}"],
    ["VITE_API_KEY", "%VITE_API_KEY_RUNTIME%"],
    ["VITE_API_KEY", "import.meta.env.API_KEY_RUNTIME"],
    ["NEXT_PUBLIC_SECRET_KEY", "changeMeToARealSecretValue"],
  ])("%s = %s", (key, value) => {
    expect(names(vite(key, value))).toEqual([]);
  });

  it("still reports a real value", () => {
    expect(names(vite("VITE_OPENAI_API_KEY", "Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0"))).toContain(
      "Secret Environment Variable Leaked in Frontend Bundle",
    );
  });
});

describe("generic 'secret' assignments: a name is not a value", () => {
  it.each([
    "S3_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY_2",
    "mySecretKeyValueHere",
    "accessTokenGoesHere",
    "supersecretjwtkeychangeme",
    "a-very-long-random-string",
    "generate-a-random-string",
    "your-super-secret-jwt-key",
  ])("secret: %s", (value) => {
    expect(names(`const cfg = { secret: "${value}" };`)).toEqual([]);
  });

  it.each([
    "Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0UoY",
    "b7f3c9a1e2d84f6a9c0b5e7d3a1f8c2e",
    "7Hq-Zk2_Rt9LxWc4Bn6Vm3Yp8Ds1Fg5J",
  ])("still reports secret: %s", (value) => {
    expect(names(`const cfg = { secret: "${value}" };`)).toContain("Hardcoded Secret or Auth Token in Source");
  });
});

describe("the helpers", () => {
  it.each([
    "S3_SECRET_ACCESS_KEY", "OPENAI_API_KEY_2", "MY_DEEPSEEK_API_KEY", "mySecretKeyValueHere",
    "accessTokenGoesHere", "supersecretjwtkeychangeme", "a-very-long-random-string", "generate-a-random-string",
    "your-super-secret-jwt-key-must-be-long!", "change-this-secret-in-production.", "your-super-secret-key-min-32-chars-long!",
  ])("looksLikeAName(%s)", (v) => expect(looksLikeAName(v)).toBe(true));

  it.each(["Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0UoY", "b7f3c9a1e2d84f6a9c0b5e7d3a1f8c2e", "AKIAQZPXMC4278HDVBNR", "correct-horse-battery-staple-9"])(
    "looksLikeAName(%s) is false", (v) => expect(looksLikeAName(v)).toBe(false),
  );

  it.each(["process.env.API_TOKEN", "${VITE_API_KEY}", "%API_KEY%", "$API_KEY", "import.meta.env.X", "env('API_KEY')", "<your key>", "{{ api_key }}"])(
    "looksLikeReference(%s)", (v) => expect(looksLikeReference(v)).toBe(true),
  );
  it("looksLikeReference is false for a real value", () => expect(looksLikeReference("Kq8Zr2Lm9Vb3Xt7")).toBe(false));

  it.each([`sk_live_${x(24)}`, `ghp_${x(36)}`, "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "sk_live_YOUR_KEY_HERE_0123456789"])(
    "isPlaceholderToken(%s)", (v) => expect(isPlaceholderToken(v)).toBe(true),
  );
  it.each(["sk_live_51JvQ8rKx2Lw9ZpTn4Uc7YhBa3DfGm", "AKIAQZPXMC4278HDVBNR"])(
    "isPlaceholderToken(%s) is false", (v) => expect(isPlaceholderToken(v)).toBe(false),
  );
});
