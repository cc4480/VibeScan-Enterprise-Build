import { describe, it, expect } from "vitest";
import { scanConfigSecrets } from "./configSecrets";

/**
 * Secrets in the syntaxes config files are actually written in. The JS-oriented patterns that the GitHub
 * source scan reused need a quoted value after a key like `secret:`, so realistic secrets in an unquoted
 * .env, a Django settings.py, a wp-config.php, an appsettings.json and a docker-compose.yml all came back
 * with zero findings (reproduced by running scanContent on each).
 */
const keys = (path: string, content: string): string[] => scanConfigSecrets(path, content).map((h) => h.key);

const REAL = "Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0Uo";

describe("scanConfigSecrets: real values in real syntaxes", () => {
  it("reads an unquoted .env", () => {
    expect(keys(".env", `PORT=3000\nJWT_SECRET=${REAL}\nDB_PASSWORD=Vt8Hq3ZmLk2Rw9Xc\nAPI_KEY=b7f3c9a1e2d84f6a9c0b5e7d3a1f8c2e\n`)).toEqual([
      "JWT_SECRET", "DB_PASSWORD", "API_KEY",
    ]);
  });

  it("reads export lines, quoted values and trailing comments", () => {
    expect(keys(".env.production", `export STRIPE_WEBHOOK_SECRET="${REAL}" # from the dashboard\nSESSION_SECRET='${REAL}'\n`)).toEqual([
      "STRIPE_WEBHOOK_SECRET", "SESSION_SECRET",
    ]);
  });

  it("reads a Django settings.py assignment", () => {
    expect(keys("app/settings.py", `SECRET_KEY = '${REAL}'\nDEBUG = True\nDATABASES = {'default': {'PASSWORD': 'Vt8Hq3ZmLk2Rw9Xc'}}\n`)).toEqual(["SECRET_KEY", "PASSWORD"]);
  });

  it("reads a wp-config.php define()", () => {
    expect(keys("wp-config.php", `define('DB_NAME', 'wordpress');\ndefine('DB_PASSWORD', 'Vt8Hq3ZmLk2Rw9Xc');\ndefine('AUTH_KEY', '${REAL}');\n`)).toEqual([
      "DB_PASSWORD", "AUTH_KEY",
    ]);
  });

  it("reads appsettings.json, including a password inside a connection string", () => {
    const json = `{ "Jwt": { "Secret": "${REAL}", "ExpiryMinutes": 60 }, "ConnectionStrings": { "Default": "Server=db.prod.acme.io;Database=app;User Id=app;Password=Vt8Hq3ZmLk2Rw9Xc;" } }`;
    expect(keys("appsettings.json", json)).toEqual(["Jwt.Secret", "ConnectionStrings.Default (Password)"]);
  });

  it("reads docker-compose environment in map and list form", () => {
    const yml = `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: Vt8Hq3ZmLk2Rw9Xc\n  api:\n    environment:\n      - JWT_SECRET=${REAL}\n`;
    expect(keys("docker-compose.yml", yml)).toEqual(["POSTGRES_PASSWORD", "JWT_SECRET"]);
  });

  it("reads terraform.tfvars and an .npmrc auth token", () => {
    expect(keys("terraform.tfvars", `db_password = "Vt8Hq3ZmLk2Rw9Xc"\nregion = "us-east-1"\n`)).toEqual(["db_password"]);
    expect(keys(".npmrc", `//registry.npmjs.org/:_authToken=${REAL}\n`)).toEqual(["//registry.npmjs.org/:_authToken"]);
  });

  it("reads a .netrc password", () => {
    expect(keys(".netrc", `machine api.acme.io\nlogin deploy\npassword ${REAL}\n`)).toEqual(["password"]);
  });

  it("redacts the value in what it returns", () => {
    const [hit] = scanConfigSecrets(".env", `JWT_SECRET=${REAL}\n`);
    expect(hit!.redacted).not.toContain(REAL);
    expect(hit!.line).toBe(1);
  });
});

describe("scanConfigSecrets: things that are not secrets", () => {
  it.each([
    ["a template", "JWT_SECRET=your-secret-here"],
    ["a placeholder word", "API_KEY=changeme"],
    ["a variable reference", "DB_PASSWORD=${DB_PASSWORD}"],
    ["a shell reference", "DB_PASSWORD=$DB_PASSWORD"],
    ["a process.env reference", "API_KEY=process.env.API_KEY"],
    ["a filler run", `API_KEY=${"x".repeat(32)}`],
    ["a tutorial default", "POSTGRES_PASSWORD=postgres"],
    ["a name", "JWT_SECRET=MY_JWT_SECRET_KEY"],
    ["an empty value", "API_KEY="],
    ["a short value", "SECRET=abc"],
    ["a boolean", "SECRET_ENABLED=true"],
    ["a setting ABOUT a secret", "JWT_SECRET_NAME=prod/jwt\nTOKEN_EXPIRY=3600\nPASSWORD_MIN_LENGTH=12\nSECRET_FILE=/run/secrets/jwt"],
    ["a comment", `# JWT_SECRET=${REAL}`],
    ["a Django dev key", "SECRET_KEY = 'django-insecure-abc123def456ghi789jkl012mno345pqr678'"],
    ["a DNS name", "API_TOKEN_URL=https://auth.acme.io/oauth/token"],
  ])("%s", (_label, content) => {
    expect(keys(".env", content)).toEqual([]);
  });

  it("is stricter on an example file, where placeholders are the norm", () => {
    // Human-chosen and low-entropy: a real .env could hold it, an .env.example almost never means it.
    expect(keys(".env.example", "DB_PASSWORD=Summer2024Acme\nJWT_SECRET=please-set-me-in-prod")).toEqual([]);
    expect(keys(".env", "DB_PASSWORD=Summer2024Acme")).toEqual(["DB_PASSWORD"]);
  });

  it("still reports an unmistakably real key in an example file", () => {
    expect(keys(".env.example", `STRIPE_WEBHOOK_SECRET=${REAL}`)).toEqual(["STRIPE_WEBHOOK_SECRET"]);
  });

  it("reports each key once and caps a file's hits", () => {
    const many = Array.from({ length: 30 }, (_, i) => `SECRET_${i}=${REAL}${i}x`).join("\n");
    expect(scanConfigSecrets(".env", many).length).toBeLessThanOrEqual(10);
    expect(keys(".env", `API_KEY=${REAL}\nAPI_KEY=${REAL}`)).toEqual(["API_KEY"]);
  });
});
