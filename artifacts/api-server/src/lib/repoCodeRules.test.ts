import { describe, it, expect } from "vitest";
import { codePatternFindings } from "./repoCheckCode";
import type { RepoFile, RepoRef } from "./repoFinding";

const ref: RepoRef = { owner: "acme", repo: "app" };
const f = (path: string, content: string): RepoFile => ({ path, content });
const names = (path: string, content: string) => codePatternFindings([f(path, content)], ref).map((v) => v.name);

describe("hardcoded JWT secrets", () => {
  it("flags a literal signing or verifying secret, never writing the secret out", () => {
    const out = codePatternFindings([f("server/auth.ts", `const token = jwt.sign({ id: user.id }, "supersecret123", { expiresIn: "1h" });`)], ref);
    expect(out.map((v) => v.name)).toEqual(["Hardcoded JWT Signing Secret"]);
    expect(out[0]!.evidence).not.toContain("supersecret123");
    expect(names("server/auth.ts", `jwt.verify(token, 'my-long-hardcoded-secret')`)).toEqual(["Hardcoded JWT Signing Secret"]);
    expect(names("server/auth.ts", `const key = new TextEncoder().encode("a-literal-jwt-secret-value"); await new SignJWT(p).sign(key);`)).toEqual(["Hardcoded JWT Signing Secret"]);
  });

  it("clean twin: a secret from the environment, a variable, or an env-var name string", () => {
    expect(names("server/auth.ts", `jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" }); jwt.verify(token, secret); jwt.verify(token, "JWT_SECRET_KEY");`)).toEqual([]);
    expect(names("server/auth.ts", `// jwt.sign(x, "an example in a comment")`)).toEqual([]);
    expect(names("server/auth.test.ts", `jwt.sign(x, "test-secret-value")`)).toEqual([]);
  });

  it("flags the none algorithm in verification options", () => {
    expect(names("server/auth.ts", `jwt.verify(token, key, { algorithms: ["HS256", "none"] })`)).toEqual(["JWT Verification Accepts the none Algorithm"]);
    expect(names("server/auth.ts", `jwt.verify(token, key, { algorithms: ["HS256"] })`)).toEqual([]);
  });
});

describe("injection from request data", () => {
  it("flags a shell command built from a request, and not execFile with an argument array", () => {
    expect(names("server/run.ts", "exec(`convert ${req.query.file} out.png`)")).toEqual(["Operating-System Command Built From Request Data"]);
    expect(names("server/run.ts", `exec("ping " + req.body.host)`)).toEqual(["Operating-System Command Built From Request Data"]);
    expect(names("server/run.ts", `execFile("convert", [file, "out.png"])`)).toEqual([]);
    expect(names("server/run.ts", `exec("ls -la")`)).toEqual([]);
  });

  it("flags a file path, a fetch URL and a redirect target taken from a request", () => {
    expect(names("server/files.ts", `res.sendFile(path.join(root, req.params.name))`)).toEqual(["File Path Taken From Request Data"]);
    expect(names("server/files.ts", `fs.readFileSync(req.query.path)`)).toEqual(["File Path Taken From Request Data"]);
    expect(names("server/proxy.ts", `const r = await fetch(req.query.url)`)).toEqual(["Server Fetches a URL Taken From Request Data"]);
    expect(names("server/go.ts", `res.redirect(req.query.next)`)).toEqual(["Redirect to an Address Taken From Request Data"]);
    expect(names("server/go.ts", `res.redirect(302, req.query.next)`)).toEqual(["Redirect to an Address Taken From Request Data"]);
  });

  it("clean twin: fixed paths, fixed URLs, a redirect to a literal", () => {
    expect(names("server/files.ts", `res.sendFile(path.join(root, "index.html")); fs.readFileSync(CONFIG_PATH)`)).toEqual([]);
    expect(names("server/proxy.ts", `await fetch("https://api.example.com/items?id=" + id)`)).toEqual([]);
    expect(names("server/go.ts", `res.redirect("/dashboard")`)).toEqual([]);
  });

  it("flags Prisma's unsafe raw query with interpolation, but not the tagged template", () => {
    expect(names("server/db.ts", "await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`)")).toEqual(["Raw SQL Built by String Concatenation or Interpolation"]);
    expect(names("server/db.ts", "await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`")).toEqual([]);
    expect(names("server/db.ts", `await prisma.$queryRawUnsafe("SELECT 1")`)).toEqual([]);
  });
});

describe("weak cryptography and cookies", () => {
  it("flags Math.random for a token and MD5 for a password", () => {
    expect(names("server/reset.ts", `const resetCode = Math.floor(Math.random() * 1000000);`)).toEqual(["Predictable Random Number Used for a Secret"]);
    expect(names("server/users.ts", `const hash = crypto.createHash("md5").update(password).digest("hex");`)).toEqual(["Password Hashed With MD5 or SHA-1"]);
    expect(names("server/users.ts", `const h = md5(user.password)`)).toEqual(["Password Hashed With MD5 or SHA-1"]);
  });

  it("clean twin: crypto randomness, a file checksum, Math.random for a layout", () => {
    expect(names("server/reset.ts", `const resetCode = crypto.randomInt(0, 1000000); const delay = Math.random() * 100;`)).toEqual([]);
    expect(names("server/files.ts", `crypto.createHash("md5").update(fileBuffer).digest("hex")`)).toEqual([]);
  });

  it("flags a cookie set with httpOnly or secure false", () => {
    expect(names("server/session.ts", `res.cookie("session", id, { httpOnly: false, maxAge: 3600 })`)).toEqual(["Session Cookie Without HttpOnly or Secure"]);
    expect(names("server/session.ts", `app.use(session({ secret: s, cookie: { secure: false } }))`)).toEqual(["Session Cookie Without HttpOnly or Secure"]);
    expect(names("server/session.ts", `res.cookie("session", id, { httpOnly: true, secure: true })`)).toEqual([]);
  });
});

describe("dangerouslySetInnerHTML", () => {
  it("flags a raw value, and leaves a literal, JSON-LD and a sanitised value alone", () => {
    expect(names("src/Post.tsx", `<div dangerouslySetInnerHTML={{ __html: post.body }} />`)).toEqual(["dangerouslySetInnerHTML With Unsanitised Content"]);
    expect(names("src/Post.tsx", `<div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />`)).toEqual([]);
    expect(names("src/Seo.tsx", `<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />`)).toEqual([]);
    expect(names("src/Post.tsx", `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />`)).toEqual([]);
  });
});

describe("API routes with no sign-in check visible", () => {
  it("flags a Next.js route handler that changes data with a service-role client and checks no one", () => {
    const route = `import { supabaseAdmin } from "@/lib/supabase";\nexport async function POST(req: Request) {\n  const body = await req.json();\n  await supabaseAdmin.from("orders").insert(body);\n  return Response.json({ ok: true });\n}\n`;
    const out = codePatternFindings([f("app/api/orders/route.ts", route)], ref);
    expect(out.map((v) => v.name)).toEqual(["API Route Changes Data With No Sign-In Check Visible"]);
    expect(out[0]!.confidence).toBeLessThan(65); // listed under "needs verification"
  });

  it("clean twin: the same route with a session lookup, or a webhook signature check", () => {
    const authed = `import { supabaseAdmin } from "@/lib/supabase";\nexport async function POST(req: Request) {\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response("no", { status: 401 });\n  await supabaseAdmin.from("orders").insert({ user_id: user.id });\n}\n`;
    expect(codePatternFindings([f("app/api/orders/route.ts", authed)], ref)).toEqual([]);
    const hook = `export async function POST(req: Request) {\n  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);\n  await prisma.order.update({ where: { id }, data: {} });\n}\n`;
    expect(codePatternFindings([f("app/api/stripe/route.ts", hook)], ref)).toEqual([]);
  });

  it("only looks at route handlers, and only at ones that change data", () => {
    const code = `import { supabaseAdmin } from "@/lib/supabase";\nexport async function POST() { await supabaseAdmin.from("t").insert({}); }`;
    expect(codePatternFindings([f("src/lib/jobs.ts", code)], ref)).toEqual([]);
    expect(codePatternFindings([f("app/api/list/route.ts", `export async function GET() { return Response.json(await prisma.item.findMany()); }`)], ref)).toEqual([]);
  });
});

describe("a committed environment file", () => {
  it("flags a real .env that sets a secret-named variable, listing names and never values", () => {
    const out = codePatternFindings([f(".env", `NODE_ENV=production\nDATABASE_URL=postgres://u:p4ssw0rd-long@db/prod\nSTRIPE_SECRET_KEY=whsec_real_looking_value_123\nPORT=3000\n`)], ref);
    expect(out.map((v) => v.name)).toEqual(["Environment File Committed to the Repository"]);
    expect(out[0]!.evidence).toContain("DATABASE_URL");
    expect(out[0]!.evidence).toContain("STRIPE_SECRET_KEY");
    expect(out[0]!.evidence).not.toContain("p4ssw0rd");
    expect(out[0]!.evidence).not.toContain("whsec_real");
  });

  it("clean twin: an example file, placeholders, empty values, public keys, plain settings", () => {
    expect(codePatternFindings([f(".env.example", `STRIPE_SECRET_KEY=whsec_real_looking_value_123`)], ref)).toEqual([]);
    expect(codePatternFindings([f(".env", `STRIPE_SECRET_KEY=your-key-here\nAPI_TOKEN=\nSECRET_KEY=changeme\nNEXT_PUBLIC_ANON_KEY=abc123abc123\nPORT=3000\nNODE_ENV=production\n`)], ref)).toEqual([]);
  });
});
