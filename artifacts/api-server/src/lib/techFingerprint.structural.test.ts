import { describe, it, expect } from "vitest";
import { detectTechnologies as d } from "./techFingerprint.js";

// Technology names feed CVE matching (TECH_CPE), so a tag earned from prose or a
// bare link becomes a HIGH "unconfirmed" advisory for software the site does not
// run. Each block: the benign page that only mentions the product (clean twin),
// then the structural evidence that must still detect it.

describe("detectTechnologies — links and prose are not platform evidence", () => {
  it("does not tag Shopify/Wix/Webflow/Squarespace from plain links", () => {
    const t = d({}, `<p>Read <a href="https://www.shopify.com/blog/x">this Shopify post</a>, <a href="https://wix.com">wix.com</a>,
      <a href="https://webflow.com">webflow.com</a>, <a href="https://squarespace.com">sq</a></p>`);
    for (const n of ["Shopify", "Wix", "Webflow", "Squarespace"]) expect(t).not.toContain(n);
  });
  it("still detects each from the asset host or generator meta", () => {
    expect(d({}, `<link href="https://cdn.shopify.com/s/x.css" rel="stylesheet">`)).toContain("Shopify");
    expect(d({}, `<script src="//static.parastorage.com/a.js"></script>`)).toContain("Wix");
    expect(d({}, `<html data-wf-site="abc" data-wf-page="def">`)).toContain("Webflow");
    expect(d({}, `<link href="https://static1.squarespace.com/x.css" rel="stylesheet">`)).toContain("Squarespace");
  });
  it("does not tag Ghost from a ghost.org link or an unrelated meta", () => {
    expect(d({}, `<a href="https://ghost.org">Ghost</a> <meta name="description" content="Ghost stories for kids">`)).not.toContain("Ghost");
  });
  it("tags Ghost from its generator meta", () => {
    expect(d({}, `<meta name="generator" content="Ghost 5.79">`)).toContain("Ghost");
    expect(d({}, `<meta content="Ghost 5.79" name="generator">`)).toContain("Ghost");
  });
});

describe("detectTechnologies — Bolt.new / Lovable", () => {
  it("does not tag either from an SEO keywords meta or prose URL", () => {
    const t = d({}, `<meta name="keywords" content="bolt.new, lovable.app, stackblitz.io, vibe coding">
      <meta property="og:description" content="Compare Bolt.new and Lovable"><p>Try https://demo.lovable.app today</p>
      <a href="https://bolt.new">Bolt</a>`);
    expect(t).not.toContain("Bolt.new");
    expect(t).not.toContain("Lovable");
  });
  it("still tags from loaded assets and the Lovable template og:image", () => {
    expect(d({}, `<script src="https://bolt.new/static/x.js"></script>`)).toContain("Bolt.new");
    expect(d({}, `<script type="module" src="https://cdn.gpteng.co/x.js"></script><script src="https://app.lovable.dev/c.js"></script>`)).toContain("Lovable");
    expect(d({}, `<meta property="og:image" content="https://lovable.dev/opengraph-image-p98pqg.png">`)).toContain("Lovable");
  });
});

describe("detectTechnologies — framework names in prose", () => {
  const prose = `<p>We migrated from gatsby to Astro. Also Vue.version, ReactDOM, Sentry.init(...) and Stripe( docs;
    nuxt.js; backbone.js; emberjs; Drupal.behaviors; supabase.co and initializeApp examples; svelte-check</p>`;
  it("tags nothing from prose", () => expect(d({}, prose)).toEqual([]));
  it("still detects each from script content or asset paths", () => {
    expect(d({}, `<div id="___gatsby"></div>`)).toContain("Gatsby");
    expect(d({}, `<meta name="generator" content="Gatsby 5.13.0">`)).toContain("Gatsby");
    expect(d({}, `<script>ReactDOM.createRoot(x)</script>`)).toContain("React");
    expect(d({}, `<script>console.log(Vue.version)</script>`)).toContain("Vue.js");
    expect(d({}, `<script src="/_nuxt/entry.js"></script>`)).toContain("Nuxt.js");
    expect(d({}, `<script>window.Ember.VERSION</script>`)).toContain("Ember.js");
    expect(d({}, `<script src="/js/backbone-min.js"></script>`)).toContain("Backbone.js");
    expect(d({}, `<div class="foo svelte-1abc2de">`)).toContain("Svelte");
  });
  it("does not tag Svelte from svelte-check / svelte-preprocess mentions", () =>
    expect(d({}, `<p>Run svelte-check, svelte-preprocess</p><div class="svelte-check">`)).not.toContain("Svelte"));
  it("supabase.co / initializeApp in prose tags neither BaaS; script content still does", () => {
    const t = d({}, `<p>See supabase.co docs and initializeApp examples</p>`);
    expect(t).not.toContain("Supabase");
    expect(t).not.toContain("Firebase");
    expect(d({}, `<script>import { initializeApp } from "firebase/app"</script>`)).toContain("Firebase");
  });
});

describe("detectTechnologies — analytics vendors", () => {
  it("does not tag vendors from links or mentions", () => {
    const t = d({}, `<a href="https://segment.com/">segment.com</a> <a href="https://hotjar.com">h</a> <a href="https://intercom.io">i</a>
      <a href="https://mixpanel.com">m</a> <a href="https://sentry.io">s</a> <a href="https://plausible.io">p</a> <p>Sentry.init( and Stripe(</p>`);
    expect(t).toEqual([]);
  });
  it("still tags each from the script it loads", () => {
    expect(d({}, `<script src="https://cdn.segment.com/analytics.js/v1/x/analytics.min.js"></script>`)).toContain("Segment");
    expect(d({}, `<script src="https://static.hotjar.com/c/hotjar-1.js"></script>`)).toContain("Hotjar");
    expect(d({}, `<script src="https://widget.intercom.io/widget/abc"></script>`)).toContain("Intercom");
    expect(d({}, `<script>mixpanel.init("t")</script>`)).toContain("Mixpanel");
    expect(d({}, `<script defer data-domain="a.com" src="https://plausible.io/js/script.js"></script>`)).toContain("Plausible Analytics");
    expect(d({}, `<script>var s = Stripe("pk_live_x")</script>`)).toContain("Stripe");
  });
});

describe("detectTechnologies — Python and header quirks", () => {
  it("does not tag Python from a tutorial page", () =>
    expect(d({}, `<html><head><title>Learn Python</title></head><body>flask, fastapi and django tutorials</body></html>`)).not.toContain("Python"));
  it("tags Python from a traceback or Django CSRF field", () => {
    expect(d({}, `<pre>Traceback (most recent call last):\n File "app.py"</pre>`)).toContain("Python");
    expect(d({}, `<input type="hidden" name="csrfmiddlewaretoken" value="x">`)).toContain("Django");
  });
  it("gunicorn is not also Unicorn; a bare Unicorn server still is", () => {
    expect(d({ server: "gunicorn/20.1" }, "")).not.toContain("Unicorn");
    expect(d({ server: "gunicorn/20.1" }, "")).toContain("Gunicorn");
    expect(d({ server: "unicorn" }, "")).toContain("Unicorn");
  });
  it("a sessionid cookie alone is not Django", () => {
    expect(d({ "set-cookie": "sessionid=abc; Path=/" }, "")).not.toContain("Django");
    expect(d({ "set-cookie": "a=1; Path=/, csrftoken=abc; Path=/" }, "")).toContain("Django");
  });
  it("generic x-served-by is not Fastly; the Fastly POP shape is", () => {
    expect(d({ "x-served-by": "varnish-01" }, "")).not.toContain("Fastly");
    expect(d({ "x-served-by": "cache-lhr123-LHR" }, "")).toContain("Fastly");
  });
  it("Apache-Coyote (Tomcat) is not Apache httpd", () => {
    expect(d({ server: "Apache-Coyote/1.1" }, "")).not.toContain("Apache");
    expect(d({ server: "Apache/2.4.58 (Ubuntu)" }, "")).toContain("Apache");
  });
});
