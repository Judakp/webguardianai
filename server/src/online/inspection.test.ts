import test from "node:test";
import assert from "node:assert/strict";
import { extractEvidence } from "./extract.js";
import type { FetchedSite } from "./fetchSite.js";
import { analyzeOnlineSite } from "./pipeline.js";
import type { HostResolver } from "./ssrf.js";

// End-to-end inspection tests. The "website" in every case is a hand-written
// mock response served by a stub fetch — no real site is ever contacted.

const resolver: HostResolver = async (host: string) => {
  if (host === "site.example") return ["93.184.216.34"];
  throw new Error(`unexpected host: ${host}`);
};

function stubFetch(
  body: string,
  headers: Record<string, string> = {},
  status = 200
): typeof fetch {
  return (async () =>
    new Response(body, {
      status,
      headers: { "content-type": "text/html; charset=utf-8", ...headers },
    })) as unknown as typeof fetch;
}

function fetched(body: string): FetchedSite {
  return {
    startUrl: "https://site.example/",
    finalUrl: "https://site.example/",
    status: 200,
    contentType: "text/html",
    headers: {},
    setCookies: [],
    body,
    bodyBytes: body.length,
    redirectHops: 0,
  };
}

function idsOf(report: { findings: Array<{ id: string }> }): Set<string> {
  return new Set(report.findings.map((f) => f.id));
}

const HARDENED = `<!doctype html><html lang="en"><head>
<title>Example Services</title>
<meta name="description" content="A hardened example page for inspection tests.">
<link rel="canonical" href="https://site.example/">
</head><body>
<h1>Welcome</h1>
<h2>Details</h2>
<p>All good.</p>
<img src="logo.png" alt="Company logo">
<a href="/about">About</a>
</body></html>`;

const HARDENED_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};

test("valid hardened HTML reports confirmations and a consistent summary", async () => {
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(HARDENED, HARDENED_HEADERS),
  });
  const ids = idsOf(report);
  for (const id of ["transport-https", "hsts-enabled", "csp-present", "framing-protected"]) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
  for (const id of ["title-missing", "meta-description-missing", "h1-missing", "images-missing-alt"]) {
    assert.ok(!ids.has(id), `unexpected ${id}`);
  }
  assert.equal(report.summary.total, report.findings.length);
  const counted = Object.values(report.summary.bySeverity).reduce((a, b) => a + b, 0);
  assert.equal(counted, report.summary.total);
  assert.ok(report.findings.every((f) => typeof f.evidence === "string" && f.evidence.length > 0));
});

test("missing title, meta description, and h1 are reported end to end", async () => {
  const body = `<!doctype html><html><head></head><body><h2>No h1 here</h2><p>Text.</p></body></html>`;
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body),
  });
  const ids = idsOf(report);
  assert.ok(ids.has("title-missing"));
  assert.ok(ids.has("meta-description-missing"));
  assert.ok(ids.has("h1-missing"));
  const h1 = report.findings.find((f) => f.id === "h1-missing");
  assert.ok(h1?.evidence?.includes("1 heading(s)"), h1?.evidence);
});

test("page with no headings at all reports h1-missing", async () => {
  const body = `<!doctype html><html><head><title>T</title></head><body><p>No headings.</p></body></html>`;
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body),
  });
  assert.ok(idsOf(report).has("h1-missing"));
});

test("images without alt text are counted with quoted samples", async () => {
  const body = `<!doctype html><html><head><title>T</title></head><body><h1>H</h1>
<img src="hero.png"><img src="team.jpg" alt=""><img src="logo.svg" alt="Logo">
</body></html>`;
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body),
  });
  const finding = report.findings.find((f) => f.id === "images-missing-alt");
  assert.ok(finding, "missing images-missing-alt");
  assert.ok(finding.evidence?.includes("hero.png"), finding.evidence);
});

test("missing security headers are flagged; present headers are confirmed", async () => {
  const body = `<!doctype html><html><head><title>T</title></head><body><h1>H</h1></body></html>`;
  const bare = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body),
  });
  const bareIds = idsOf(bare);
  for (const id of ["hsts-missing", "csp-missing", "framing-unprotected"]) {
    assert.ok(bareIds.has(id), `missing ${id}`);
  }
  const sealed = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body, HARDENED_HEADERS),
  });
  const sealedIds = idsOf(sealed);
  for (const id of ["hsts-missing", "csp-missing", "framing-unprotected"]) {
    assert.ok(!sealedIds.has(id), `unexpected ${id}`);
  }
  assert.ok(sealedIds.has("framing-protected"));
});

test("malformed HTML never crashes extraction and yields best-effort evidence", () => {
  const cases = [
    "<html><head><title>Unclosed",
    "<!doctype html><html><body><h1>Hi<img src=x><a href=/a>link<p>para",
    "<title>&lt;weird &amp; entities&#x41;&#66;</title><h1></h1>",
    "<html><head><title>First</title><title>Second</title></head><body></body>",
    "<script>var s = '</scr' + 'ipt>';</script><h1>After script</h1>",
    "not html at all, just text",
    "<a href>empty href</a><img><form><input type=password>",
  ];
  for (const body of cases) {
    const evidence = extractEvidence(fetched(body));
    assert.ok(typeof evidence.title === "string" || evidence.title === null, body);
    assert.ok(Array.isArray(evidence.links), body);
    assert.ok(Array.isArray(evidence.headings), body);
    assert.ok(Number.isInteger(evidence.imagesMissingAlt), body);
  }
  const truncated = extractEvidence(fetched("<html><head><title>Unclosed"));
  assert.equal(truncated.title, null);
  const entities = extractEvidence(fetched("<title>&lt;weird &amp; entities&#x41;&#66;</title>"));
  assert.equal(entities.title, "<weird & entitiesAB");
});

test("malformed page still produces a full report end to end", async () => {
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch("<html><body><h1>Hi<img src=x><a href=/a>oops"),
  });
  assert.equal(report.mode, "online");
  assert.equal(report.summary.total, report.findings.length);
  assert.ok(idsOf(report).has("title-missing"));
});

test("empty page analyzes without crashing", async () => {
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(""),
  });
  const ids = idsOf(report);
  assert.ok(ids.has("title-missing"));
  assert.ok(ids.has("h1-missing"));
  assert.equal(report.summary.total, report.findings.length);
});

test("a throwing link verifier falls back to honest not-evaluated", async () => {
  const body = `<!doctype html><html><head><title>T</title></head>
<body><h1>H</h1><a href="/a">a</a></body></html>`;
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body),
    linkVerifier: async () => {
      throw new Error("verifier exploded");
    },
  });
  const ids = idsOf(report);
  assert.ok(ids.has("links-live-check-not-evaluated"));
  assert.ok(!ids.has("link-broken"));
  assert.ok(!ids.has("links-verified"));
});

test("broken link samples are reported with status evidence", async () => {
  const body = `<!doctype html><html><head><title>T</title></head>
<body><h1>H</h1><a href="/ok">ok</a><a href="/gone">gone</a></body></html>`;
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(body),
    linkVerifier: async (urls) =>
      urls.map((href) => (href.endsWith("/gone") ? { href, ok: false, status: 404 } : { href, ok: true, status: 200 })),
  });
  const broken = report.findings.find((f) => f.id === "link-broken");
  assert.ok(broken, "missing link-broken");
  assert.ok(broken.evidence?.includes("404"), broken.evidence);
  assert.ok(broken.evidence?.includes("/gone"), broken.evidence);
  assert.ok(!idsOf(report).has("links-live-check-not-evaluated"));
});
