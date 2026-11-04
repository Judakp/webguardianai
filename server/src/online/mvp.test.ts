import test from "node:test";
import assert from "node:assert/strict";
import { createEmptyReport, summarizeFindings } from "webguardian-shared";
import { deterministicEngineFinding, getAiStatus } from "./ai.js";
import { dedupeFindings, runOnlineChecks } from "./checks.js";
import { extractEvidence, type SiteEvidence } from "./extract.js";
import type { FetchedSite } from "./fetchSite.js";
import { analyzeOnlineSite } from "./pipeline.js";
import type { HostResolver } from "./ssrf.js";

function fetched(body: string, finalUrl = "https://example.com/"): FetchedSite {
  return {
    startUrl: finalUrl,
    finalUrl,
    status: 200,
    contentType: "text/html",
    headers: {},
    setCookies: [],
    body,
    bodyBytes: body.length,
    redirectHops: 0,
  };
}

function richEvidence(): SiteEvidence {
  return {
    startUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    finalIsHttps: true,
    status: 200,
    headers: {},
    setCookies: [],
    redirectHops: 0,
    title: "Example",
    metaDescription: "Desc",
    metaCount: 2,
    canonical: null,
    robotsMeta: null,
    htmlLang: null,
    headings: [{ level: 1, text: "Hi" }],
    headingTotal: 1,
    h1Count: 1,
    headingSkips: [],
    links: [],
    linkTotal: 0,
    internalLinkTotal: 0,
    externalLinkTotal: 0,
    suspiciousLinks: [],
    scripts: [],
    scriptTotal: 0,
    inlineScriptCount: 0,
    forms: [],
    formTotal: 0,
    imagesMissingAlt: 0,
    imageTotal: 0,
    imageSample: [],
    inlineHandlerCount: 0,
    inlineHandlerSample: [],
    jsHrefCount: 0,
    jsHrefSample: [],
    subresourceHttp: [],
    subresourceHttpTotal: 0,
    stylesheetTotal: 0,
    cssSample: [],
  };
}

test("ai status reports the integration blocker without faking output", () => {
  const status = getAiStatus();
  assert.equal(status.available, false);
  assert.match(status.reason ?? "", /MODEL_API_KEY|Muse Spark/);
  const banner = deterministicEngineFinding();
  assert.equal(banner.id, "engine-deterministic");
  assert.equal(banner.severity, "info");
  assert.equal(banner.category, "Technical");
  assert.ok(banner.description && banner.whyItMatters && banner.evidence && banner.recommendation);
  assert.equal(banner.confidence, "high");
});

test("shared contracts count the critical severity", () => {
  assert.equal(createEmptyReport("online", "r").summary.bySeverity.critical, 0);
  const summary = summarizeFindings([
    { id: "a", title: "t", severity: "critical" },
    { id: "b", title: "t", severity: "high" },
  ]);
  assert.equal(summary.total, 2);
  assert.equal(summary.bySeverity.critical, 1);
  assert.equal(summary.bySeverity.high, 1);
});

test("extraction captures canonical, robots, lang, hierarchy, and suspicious links", () => {
  const body = `<!doctype html><html lang="en"><head>
<title>T</title><meta name="description" content="d">
<meta name="robots" content="noindex, nofollow">
<link rel="canonical" href="https://example.com/page">
<link rel="stylesheet" href="https://cdn.example/app.css">
</head><body>
<h1>One</h1><h1>Two</h1><h3>Skipped</h3>
<a href="/in">in</a>
<a href="https://example.com@evil.example/">creds</a>
<a href="http://93.184.216.34/x">ip</a>
<a href="https://example.com/real">https://other.example/fake</a>
</body></html>`;
  const evidence = extractEvidence(fetched(body));
  assert.equal(evidence.htmlLang, "en");
  assert.equal(evidence.canonical, "https://example.com/page");
  assert.equal(evidence.robotsMeta, "noindex, nofollow");
  assert.equal(evidence.h1Count, 2);
  assert.deepEqual(evidence.headingSkips, ["h1 → h3"]);
  assert.equal(evidence.internalLinkTotal, 2);
  assert.equal(evidence.externalLinkTotal, 2);
  assert.equal(evidence.suspiciousLinks?.length, 3);
  assert.ok(evidence.suspiciousLinks?.some((s) => s.includes("credentials")));
  assert.ok(evidence.suspiciousLinks?.some((s) => s.includes("literal IP")));
  assert.ok(evidence.suspiciousLinks?.some((s) => s.includes("different address")));
  assert.deepEqual(evidence.cssSample, ["https://cdn.example/app.css"]);
});

test("every check finding carries category, description, why-it-matters, and confidence", () => {
  const evidence = richEvidence();
  evidence.links = [
    { href: "https://example.com/a", text: "a", external: false, http: false, targetBlank: false, rel: "" },
  ];
  evidence.linkTotal = 1;
  evidence.internalLinkTotal = 1;
  for (const finding of runOnlineChecks(evidence)) {
    assert.ok(finding.category, `${finding.id} missing category`);
    assert.ok(finding.description, `${finding.id} missing description`);
    assert.ok(finding.whyItMatters, `${finding.id} missing whyItMatters`);
    assert.ok(finding.confidence, `${finding.id} missing confidence`);
    assert.ok(typeof finding.evidence === "string", `${finding.id} missing evidence`);
    assert.ok(typeof finding.recommendation === "string", `${finding.id} missing recommendation`);
  }
});

test("new seo, a11y, performance, and link checks fire on grounded evidence", () => {
  const evidence = richEvidence();
  evidence.title = "x".repeat(61);
  evidence.metaDescription = "y".repeat(161);
  evidence.robotsMeta = "noindex";
  evidence.h1Count = 2;
  evidence.headingSkips = ["h1 → h3"];
  evidence.suspiciousLinks = ["https://example.com@evil.example/ (URL contains credentials)"];
  evidence.links = [
    { href: "https://example.com/a", text: "a", external: false, http: false, targetBlank: false, rel: "" },
  ];
  evidence.linkTotal = 1;
  evidence.internalLinkTotal = 1;
  evidence.scripts = [
    { src: "https://cdn.example/a.js", external: true, http: false, async: false, defer: false, integrity: true },
  ];
  evidence.forms = [{ action: "http://example.com/s", external: false, http: true, method: "get", hasPassword: false }];
  evidence.formTotal = 1;
  const ids = new Map(runOnlineChecks(evidence).map((f) => [f.id, f]));
  for (const id of [
    "canonical-missing",
    "html-lang-missing",
    "title-too-long",
    "meta-description-too-long",
    "robots-directives",
    "multiple-h1",
    "heading-order-skipped",
    "suspicious-links",
    "links-live-check-not-evaluated",
    "render-blocking-scripts",
    "form-submits-over-http",
  ]) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
  assert.equal(ids.get("multiple-h1")?.severity, "low");
  assert.equal(ids.get("heading-order-skipped")?.severity, "low");
  assert.equal(ids.get("suspicious-links")?.confidence, "medium");
  assert.equal(ids.get("title-too-long")?.category, "SEO");
  assert.equal(ids.get("render-blocking-scripts")?.category, "Performance");
});

test("verified link samples report broken links; unverified links stay honest", () => {
  const checked = richEvidence();
  checked.linkChecks = [
    { href: "https://example.com/ok", ok: true, status: 200 },
    { href: "https://example.com/gone", ok: false, status: 404 },
  ];
  const checkedIds = runOnlineChecks(checked).map((f) => f.id);
  assert.ok(checkedIds.includes("link-broken"));
  assert.ok(!checkedIds.includes("links-verified"));
  assert.ok(!checkedIds.includes("links-live-check-not-evaluated"));

  const allOk = richEvidence();
  allOk.linkChecks = [{ href: "https://example.com/ok", ok: true, status: 200 }];
  const allOkIds = runOnlineChecks(allOk).map((f) => f.id);
  assert.ok(allOkIds.includes("links-verified"));
});

test("dedupe removes exact duplicates and keeps per-instance findings", () => {
  const dup = {
    id: "x",
    title: "t",
    severity: "low" as const,
    evidence: "e",
    recommendation: "r",
  };
  const out = dedupeFindings([
    dup,
    { ...dup },
    { ...dup, evidence: "other" },
  ]);
  assert.equal(out.length, 2);
});

const resolver: HostResolver = async (host: string) => {
  if (host === "site.example") return ["93.184.216.34"];
  throw new Error(`unexpected host: ${host}`);
};

function stubFetch(body: string): typeof fetch {
  return (async () =>
    new Response(body, { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
}

test("pipeline labels deterministic engine, urls, and honors a mock link verifier", async () => {
  const html = `<!doctype html><html><head><title>Stub</title></head>
<body><h1>Hi</h1><a href="/a">a</a><a href="/b">b</a></body></html>`;
  const seen: string[][] = [];
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(html),
    linkVerifier: async (urls) => {
      seen.push(urls);
      return urls.map((href) =>
        href.endsWith("/b") ? { href, ok: false, status: 404 } : { href, ok: true, status: 200 }
      );
    },
  });
  assert.equal(report.engine?.kind, "deterministic");
  assert.equal(report.engine?.aiAvailable, false);
  assert.match(report.engine?.aiBlocker ?? "", /MODEL_API_KEY|Muse Spark/);
  assert.equal(report.analyzedUrl, "https://site.example/");
  assert.equal(report.finalUrl, "https://site.example/");
  assert.deepEqual(seen, [["https://site.example/a", "https://site.example/b"]]);
  const ids = report.findings.map((f) => f.id);
  assert.ok(ids.includes("engine-deterministic"));
  assert.ok(ids.includes("link-broken"));
  assert.ok(!ids.includes("links-live-check-not-evaluated"));
  assert.equal(report.summary.total, report.findings.length);
});

test("pipeline without a verifier reports links as not evaluated", async () => {
  const html = `<!doctype html><html><head><title>Stub</title></head>
<body><h1>Hi</h1><a href="/a">a</a></body></html>`;
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver,
    fetchImpl: stubFetch(html),
  });
  const ids = report.findings.map((f) => f.id);
  assert.ok(ids.includes("links-live-check-not-evaluated"));
  assert.ok(!ids.includes("link-broken"));
});
