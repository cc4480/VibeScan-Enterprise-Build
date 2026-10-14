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

describe("scanConfigSecrets: shell interpolation is a reference", () => {
  it("does not read the inside of ${VAR:?message} or ${VAR:-default} as a value", () => {
    const compose = [
      "services:",
      "  db:",
      "    environment:",
      "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}",
      "      ENCRYPTION_KEY: ${ENCRYPTION_KEY:?ENCRYPTION_KEY must be set}",
      "      API_TOKEN: ${API_TOKEN:-fallbackvalue123}",
    ].join("\n");
    expect(scanConfigSecrets("docker-compose.yml", compose)).toEqual([]);
  });
});

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

// ─── Public-by-design keys and development-default passwords ─────────────────

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload: object) => `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64(payload)}.Xk3l9sQ2vB7nRt0yUe1WmA5cHzPq8dJf4oLg6iYh2Zs`;
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1700000000, exp: 2000000000 });
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role", iat: 1700000000, exp: 2000000000 });
const MAPBOX = "pk.eyJ1IjoiYWNtZSIsImEiOiJjbGFiY2RlZmcwMDAwM3BwbnZ4In0.abcDEF123ghiJKL456mnoPQR";

describe("scanConfigSecrets: public-by-design keys and dev passwords", () => {
  it.each([
    "NEXT_PUBLIC_FIREBASE_API_KEY=AIzaSyD4x9Kq2LmN8pRt3VwYz1AbCdEfGhIjKlM",
    "NEXT_PUBLIC_MAPBOX_TOKEN=pk.eyJ1IjoiYWNtZSIsImEiOiJjbGx4OXl6eDkwMDFhM3FwZjFyaG5ld3ByIn0.aBcDeFgHiJkLmNoPqRsTuV",
    "ALGOLIA_SEARCH_API_KEY=8f3a1c7b9d2e4f60a5b7c8d9e0f1a2b3",
    "GOOGLE_MAPS_API_KEY=AIzaSyB1c2D3e4F5g6H7i8J9k0LmNoPqRsTuVwX",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_51Hq3kLJx8vN2mYtRzWc9aBdE0fGhIjKlMnOpQrStUv",
    `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON}`,
    "NEXT_PUBLIC_POSTHOG_KEY=phc_Zq3XkL8vN2mYtRzWc9aBdE0fGhIjKlMnOpQrSt",
  ])("%s", (line) => {
    expect(keys(".env", line)).toEqual([]);
  });

  it("does not report dev-default passwords in docker-compose", () => {
    const compose = "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: devpassword\n      MYSQL_ROOT_PASSWORD: rootpassword\n";
    expect(keys("docker-compose.yml", compose)).toEqual([]);
    for (const pw of ["password123", "changeme", "example", "test", "secret", "admin", "adminpassword", "testpass1"]) {
      expect(keys(".env", `DB_PASSWORD=${pw}`)).toEqual([]);
    }
  });

  it("does not read a SQL comment as a config pair", () => {
    expect(keys("supabase/migrations/1.sql", `-- api_key: "test_key_value_1234"\n`)).toEqual([]);
  });

  it("still reports real secrets beside public ones", () => {
    const env = `NEXT_PUBLIC_FIREBASE_API_KEY=AIzaSyD4x9Kq2LmN8pRt3VwYz1AbCdEfGhIjKlM\nSTRIPE_SECRET_KEY=sk_live_51Hq3kLJx8vN2mYtRzWc9aBdE0fGhIj\nDB_PASSWORD=Summer2024Acme\nSUPABASE_SERVICE_ROLE_KEY=${SERVICE}\nALGOLIA_ADMIN_API_KEY=8f3a1c7b9d2e4f60a5b7c8d9e0f1a2b3\n`;
    expect(keys(".env", env)).toEqual(["STRIPE_SECRET_KEY", "DB_PASSWORD", "SUPABASE_SERVICE_ROLE_KEY", "ALGOLIA_ADMIN_API_KEY"]);
  });
});

describe("code and shell commands are not committed secrets", () => {
  it("does not read a command substitution in a CI file as a value", () => {
    expect(keys(".github/workflows/ci.yml", "env:\n  ENCRYPTION_KEY: $(openssl rand -hex 32)\n")).toEqual([]);
  });

  it("does not read a function call or an environment read in source as a value", () => {
    expect(keys("server/config.ts", "  healthDetailToken: clean(process.env.HEALTH_DETAIL_TOKEN),\n  apiToken: process.env.API_TOKEN ?? '',\n")).toEqual([]);
  });

  it("in source code, reads a quoted literal but not a bare expression", () => {
    expect(keys("src/pay.ts", `const apiSecret = "${REAL}";\n`)).toEqual(["apiSecret"]);
    expect(keys("src/pay.ts", `const authToken = ${REAL};\n`)).toEqual([]);
  });

  it("in a config file, still reads an unquoted value", () => {
    expect(keys("deploy/app.env", `API_SECRET=${REAL}\n`)).toEqual(["API_SECRET"]);
  });
});

describe("found in real repositories: not secrets", () => {
  it("fetch's credentials option is a mode, not a credential", () => {
    expect(keys("src/ui/app.js", `fetch(url, { credentials: "same-origin" }); fetch(u, { credentials: 'include' });`)).toEqual([]);
  });

  it("a plain lowercase word as a database password in a compose, CI or dev file is a development default", () => {
    const compose = `services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: complyscan\n`;
    const hit = scanConfigSecrets("docker-compose.yml", compose);
    expect(hit.map((h) => h.key)).toEqual(["POSTGRES_PASSWORD"]);
    expect(hit[0]!.devDefault).toBe(true);
    const ci = `jobs:\n  test:\n    services:\n      postgres:\n        env:\n          POSTGRES_PASSWORD: complyscan\n`;
    expect(scanConfigSecrets(".github/workflows/ci.yml", ci)[0]!.devDefault).toBe(true);
  });

  it("is not a development default when the file is not a dev file, or the password looks generated", () => {
    expect(scanConfigSecrets(".env", `POSTGRES_PASSWORD=complyscan\n`)[0]!.devDefault).toBe(false);
    expect(scanConfigSecrets("docker-compose.yml", `    environment:\n      POSTGRES_PASSWORD: Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs\n`)[0]!.devDefault).toBe(false);
    expect(scanConfigSecrets("docker-compose.yml", `    environment:\n      POSTGRES_PASSWORD: complyscan2026x\n`)[0]!.devDefault).toBe(false);
  });
});
