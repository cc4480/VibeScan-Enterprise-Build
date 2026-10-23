import { describe, it, expect } from "vitest";
import { extractSignupForm, buildFormBody, visibleText } from "./signupForm";
import { requiresEmailVerification, locationHintsVerification, isLoginShapedUrl, CookieJar } from "./signupOutcome";

const PAGE = "https://shop.example/signup";
const fields = `<input type="email" name="email"><input type="password" name="password">`;

describe("extractSignupForm: the form decides, not the page around it", () => {
  it.each([
    ["a Sign up button", `<form action="/x">${fields}<button>Sign up</button></form>`],
    ["Sign-up with a hyphen", `<form action="/x">${fields}<button>Sign-up</button></form>`],
    ["Signup as one word", `<form action="/x">${fields}<button>Signup</button></form>`],
    ["Create your free account", `<form action="/x">${fields}<button>Create your free account</button></form>`],
    ["a non-breaking space", `<form action="/x">${fields}<button>Sign&nbsp;up</button></form>`],
    ["Start your free trial", `<form action="/x">${fields}<button>Start your free trial</button></form>`],
    ["Get started", `<form action="/x">${fields}<button>Get started</button></form>`],
    ["a submit input's value", `<form action="/x">${fields}<input type="submit" value="Register"></form>`],
    ["a repeated password field, whatever the wording", `<form action="/x">${fields}<input type="password" name="confirm"><button>Continue</button></form>`],
    ["a signup-shaped action, whatever the wording", `<form action="/api/register">${fields}<button>Continue</button></form>`],
  ])("accepts %s", (_label, html) => {
    expect(extractSignupForm(html, PAGE)).not.toBeNull();
  });

  it.each([
    ["a login form on a page that says Sign up elsewhere", `<nav>Login / Register</nav><form action="/login">${fields}<button>Log in</button></form><p>Don't have an account? Sign up</p>`],
    ["a login form at a login URL", `<form action="/session">${fields}<button>Sign in</button></form>`],
    ["a service worker registration in a script", `<script>navigator.serviceWorker.register("/sw.js")</script><form action="/x">${fields}<button>Continue</button></form>`],
    ["a newsletter footer", `<form action="/x">${fields}<button>Continue</button></form><footer>Join our newsletter</footer>`],
    ["a form with no password", `<form action="/signup"><input type="email" name="email"><button>Sign up</button></form>`],
    ["a form with no email", `<form action="/signup"><input type="text" name="user"><input type="password" name="p"><button>Sign up</button></form>`],
  ])("rejects %s", (_label, html) => {
    expect(extractSignupForm(html, PAGE)).toBeNull();
  });

  it("rejects a form on a page it was redirected to a login URL for", () => {
    expect(extractSignupForm(`<form>${fields}<button>Sign up</button></form>`, "https://shop.example/login")).toBeNull();
  });

  it("does not throw on a malformed or non-http action", () => {
    expect(extractSignupForm(`<form action="http://">${fields}<button>Sign up</button></form>`, PAGE)).toBeNull();
    expect(extractSignupForm(`<form action="javascript:void(0)">${fields}<button>Sign up</button></form>`, PAGE)).toBeNull();
  });

  it("forces a GET form to POST so the password never rides in the URL", () => {
    expect(extractSignupForm(`<form method="get" action="/signup">${fields}<button>Sign up</button></form>`, PAGE)?.method).toBe("POST");
  });

  it("prefers the form with stronger evidence, wherever it sits on the page", () => {
    const html =
      `<form action="/login">${fields}<button>Log in</button></form>` +
      `<form action="/join">${fields}<input type="password" name="confirm"><button>Create account</button></form>`;
    expect(extractSignupForm(html, PAGE)?.action).toBe("https://shop.example/join");
  });
});

describe("buildFormBody", () => {
  const form = extractSignupForm(
    `<form action="/signup">${fields}<input type="hidden" name="csrf" value="tok"><input name="username"><input name="first_name">` +
      `<input type="checkbox" name="accept_terms" value="yes"><input type="checkbox" name="promo_emails"><input type="radio" name="plan" value="pro"><button>Sign up</button></form>`,
    PAGE,
  )!;

  it("fills email and password, keeps hidden fields, fills obvious name fields", () => {
    const body = buildFormBody(form, "a@example.com", "Pw1!");
    expect(body.get("email")).toBe("a@example.com");
    expect(body.get("password")).toBe("Pw1!");
    expect(body.get("csrf")).toBe("tok");
    expect(body.get("username")).toMatch(/^secscan-[0-9a-f]{8}$/);
    expect(body.get("first_name")).toBe("SecScan");
  });

  it("ticks a terms box but not a marketing box, and never guesses a radio", () => {
    const body = buildFormBody(form, "a@example.com", "Pw1!");
    expect(body.get("accept_terms")).toBe("yes");
    expect(body.has("promo_emails")).toBe(false);
    expect(body.has("plan")).toBe(false);
  });
});

describe("visibleText", () => {
  it("drops scripts, styles, comments and tags, and decodes the common entities", () => {
    expect(visibleText(`<p>Hello&nbsp;<b>there</b></p><script>var a="x"</script><style>p{}</style><!-- c -->&amp;`)).toBe("Hello there &");
  });
});

describe("requiresEmailVerification", () => {
  it.each([
    "Check your email", "check your inbox", "We sent a confirmation link to your email.", "Please verify your account",
    "confirm your e-mail", "confirmation email", "activate your account", "Enter the 6-digit code we sent",
    `{"status":"pending_verification","email_verified":false}`, "Almost there!", "Your email has been sent",
    "Please verify your email to unlock all features",
  ])("recognises %j", (text) => {
    expect(requiresEmailVerification(text)).toBe(true);
  });

  it.each([
    `{"ok":true,"user":{"email":"x@example.com"},"consent":true}`,
    "We value your consent. Your email is safe with us.",
    "Welcome back! Your orders and invoices are below.",
    "<script>var m='check your email later'</script><p>Welcome</p>",
    "Present your ticket. Represent your team. Absent members are listed.",
    "sentence structure email",
  ])("does not read verification into %j", (text) => {
    expect(requiresEmailVerification(text)).toBe(false);
  });
});

describe("locationHintsVerification and isLoginShapedUrl", () => {
  it.each(["/check-your-email", "/verify?token=abc", "/confirm-email", "/account/activate", "/otp", "/2fa", "/email-sent"])(
    "%s is a verification step", (p) => expect(locationHintsVerification(`https://a.example${p}`)).toBe(true),
  );
  it.each(["/dashboard", "/welcome", "/app/home"])("%s is not", (p) => expect(locationHintsVerification(`https://a.example${p}`)).toBe(false));
  it.each(["/login", "/sign-in", "/auth/login", "/session", "/sessions/new"])("%s is a login URL", (p) => expect(isLoginShapedUrl(`https://a.example${p}`)).toBe(true));
  it.each(["/signup", "/register", "/dashboard", "/login-help-center-article-list"])("%s is not", (p) => {
    expect(isLoginShapedUrl(`https://a.example${p}`)).toBe(false);
  });
});

describe("CookieJar keeps cookies the way a browser would", () => {
  it("keeps a value, replaces it later, and joins several", () => {
    const jar = new CookieJar();
    jar.absorb(["sid=one; Path=/; HttpOnly", "theme=dark"]);
    jar.absorb(["sid=two; Path=/"]);
    expect(jar.header()).toBe("sid=two; theme=dark");
  });
  it("drops an empty cookie, a Max-Age=0 cookie and an expired one", () => {
    const jar = new CookieJar();
    jar.absorb(["a=1", "b=2", "c=3"]);
    jar.absorb(["a=; Path=/", "b=x; Max-Age=0", "c=y; Expires=Thu, 01 Jan 1970 00:00:00 GMT"]);
    expect(jar.header()).toBeNull();
  });
  it("keeps a cookie whose Expires is in the future", () => {
    const jar = new CookieJar();
    jar.absorb([`sid=abc; Expires=${new Date(Date.now() + 86_400_000).toUTCString()}`]);
    expect(jar.header()).toBe("sid=abc");
  });
  it("is empty when nothing was set", () => {
    expect(new CookieJar().header()).toBeNull();
  });
});
