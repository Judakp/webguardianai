import test from "node:test";
import assert from "node:assert/strict";
import type { SiteEvidence } from "./extract.js";
import { runOnlineChecks } from "./checks.js";

function baseEvidence(): SiteEvidence {
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
    headings: [],
    headingTotal: 0,
    links: [],
    linkTotal: 0,
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
  };
}

function idsOf(evidence: SiteEvidence): Map<string, string> {
  return new Map(runOnlineChecks(evidence).map((f) => [f.id, f.severity]));
}

test("hardened page reports info confirmations, no highs", () => {
  const evidence = baseEvidence();
  evidence.headers = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
  };
  const ids = idsOf(evidence);
  assert.equal(ids.get("transport-https"), "info");
  assert.equal(ids.get("hsts-enabled"), "info");
  assert.equal(ids.get("csp-present"), "info");
  assert.equal(ids.get("framing-protected"), "info");
  for (const [id, severity] of ids) {
    assert.ok(severity === "info", `${id} unexpectedly ${severity}`);
  }
});

test("plain http page raises high transport finding, skips misattributed checks", () => {
  const evidence = baseEvidence();
  evidence.startUrl = "http://example.com/";
  evidence.finalUrl = "http://example.com/";
  evidence.finalIsHttps = false;
  const ids = idsOf(evidence);
  assert.equal(ids.get("transport-plain-http"), "high");
  assert.equal(ids.get("hsts-not-evaluated"), "info");
  assert.equal(ids.get("mixed-content-not-evaluated"), "info");
  assert.ok(!ids.has("hsts-missing"), "must not fail HSTS on an http page");
});

test("https upgrade is confirmed, not flagged", () => {
  const evidence = baseEvidence();
  evidence.startUrl = "http://example.com/";
  evidence.redirectHops = 1;
  const ids = idsOf(evidence);
  assert.equal(ids.get("transport-upgrades-to-https"), "info");
  assert.ok(!ids.has("transport-plain-http"));
});

test("missing headers produce grounded mediums and lows", () => {
  const ids = idsOf(baseEvidence());
  assert.equal(ids.get("hsts-missing"), "medium");
  assert.equal(ids.get("csp-missing"), "medium");
  assert.equal(ids.get("framing-unprotected"), "medium");
  assert.equal(ids.get("content-type-options-missing"), "low");
  assert.equal(ids.get("referrer-policy-missing"), "info");
});

test("weak hsts max-age is low, not missing", () => {
  const evidence = baseEvidence();
  evidence.headers = { "strict-transport-security": "max-age=60" };
  const ids = idsOf(evidence);
  assert.equal(ids.get("hsts-weak"), "low");
  assert.ok(!ids.has("hsts-missing"));
});

test("csp frame-ancestors satisfies framing protection", () => {
  const evidence = baseEvidence();
  evidence.headers = { "content-security-policy": "default-src 'self'; frame-ancestors 'none'" };
  const ids = idsOf(evidence);
  assert.equal(ids.get("framing-protected"), "info");
  assert.ok(!ids.has("framing-unprotected"));
});

test("insecure cookies are flagged per cookie", () => {
  const evidence = baseEvidence();
  evidence.setCookies = ["sess=abc; Path=/", "prefs=x; Path=/; Secure; HttpOnly; SameSite=Lax"];
  const findings = runOnlineChecks(evidence);
  const sess = findings.filter((f) => f.title.includes('"sess"'));
  assert.deepEqual(
    sess.map((f) => f.id).sort(),
    ["cookie-missing-httponly", "cookie-missing-samesite", "cookie-missing-secure"]
  );
  assert.ok(findings.every((f) => !f.title.includes('"prefs"')));
});

test("no cookies marks cookie checks unavailable, not failed", () => {
  const ids = idsOf(baseEvidence());
  assert.equal(ids.get("cookies-not-evaluated"), "info");
  assert.ok(![...ids.keys()].some((id) => id.startsWith("cookie-missing")));
});

test("http subresources on https pages are high with quoted urls", () => {
  const evidence = baseEvidence();
  evidence.subresourceHttp = ["http://cdn.example/old.css"];
  evidence.subresourceHttpTotal = 1;
  const findings = runOnlineChecks(evidence);
  const mixed = findings.find((f) => f.id === "mixed-content-http-subresource");
  assert.equal(mixed?.severity, "high");
  assert.ok(mixed?.evidence?.includes("http://cdn.example/old.css"));
});

test("password form over http is high, over https is info", () => {
  const bad = baseEvidence();
  bad.forms = [{ action: "http://example.com/login", external: false, http: true, method: "post", hasPassword: true }];
  bad.formTotal = 1;
  assert.equal(idsOf(bad).get("password-form-over-http"), "high");

  const good = baseEvidence();
  good.forms = [{ action: "https://example.com/login", external: false, http: false, method: "post", hasPassword: true }];
  good.formTotal = 1;
  assert.equal(idsOf(good).get("password-form-https"), "info");
  assert.ok(!idsOf(good).has("password-form-over-http"));
});

test("no forms marks form checks unavailable", () => {
  assert.equal(idsOf(baseEvidence()).get("forms-not-evaluated"), "info");
});

test("inline handlers, js hrefs, blank targets, and missing sri are lows", () => {
  const evidence = baseEvidence();
  evidence.inlineHandlerCount = 2;
  evidence.inlineHandlerSample = ["<button> onclick="];
  evidence.jsHrefCount = 1;
  evidence.jsHrefSample = ["javascript:void(0)"];
  evidence.links = [
    { href: "https://x.example/", text: "x", external: true, http: false, targetBlank: true, rel: "" },
  ];
  evidence.scripts = [
    { src: "https://cdn.example/a.js", external: true, http: false, async: false, defer: false, integrity: false },
  ];
  const ids = idsOf(evidence);
  assert.equal(ids.get("inline-event-handlers"), "low");
  assert.equal(ids.get("javascript-href"), "low");
  assert.equal(ids.get("blank-without-noopener"), "low");
  assert.equal(ids.get("script-missing-sri"), "low");
});

test("permissive csp script sources are medium, tight csp is not flagged", () => {
  const loose = baseEvidence();
  loose.headers = { "content-security-policy": "default-src * 'unsafe-inline'" };
  const looseFindings = runOnlineChecks(loose);
  const weak = looseFindings.find((f) => f.id === "csp-permissive-script-sources");
  assert.equal(weak?.severity, "medium");
  assert.ok(weak?.evidence?.includes("default-src"));
  assert.ok(looseFindings.some((f) => f.id === "csp-present"), "csp-present info is kept");

  const tight = baseEvidence();
  tight.headers = { "content-security-policy": "default-src 'self'" };
  assert.ok(!idsOf(tight).has("csp-permissive-script-sources"));
});

test("csp script-src takes precedence over default-src; nonces excuse unsafe-inline", () => {
  const viaScriptSrc = baseEvidence();
  viaScriptSrc.headers = { "content-security-policy": "default-src 'self'; script-src https:" };
  const viaIds = runOnlineChecks(viaScriptSrc).find((f) => f.id === "csp-permissive-script-sources");
  assert.equal(viaIds?.severity, "medium");
  assert.ok(viaIds?.evidence?.startsWith("script-src:"));

  const nonced = baseEvidence();
  nonced.headers = { "content-security-policy": "script-src 'nonce-r4nd0m' 'unsafe-inline'" };
  assert.ok(!idsOf(nonced).has("csp-permissive-script-sources"));
});

test("only deny and sameorigin count as frame protection", () => {
  const bogus = baseEvidence();
  bogus.headers = { "x-frame-options": "ALLOW-FROM https://example.com" };
  const bogusFindings = runOnlineChecks(bogus);
  assert.equal(idsOf(bogus).get("framing-unprotected"), "medium");
  assert.ok(!idsOf(bogus).has("framing-protected"));
  assert.ok(bogusFindings.find((f) => f.id === "framing-unprotected")?.evidence?.includes("ALLOW-FROM"));

  const lower = baseEvidence();
  lower.headers = { "x-frame-options": "sameorigin" };
  assert.equal(idsOf(lower).get("framing-protected"), "info");
});

test("hsts without includesubdomains adds a low alongside the info", () => {
  const evidence = baseEvidence();
  evidence.headers = { "strict-transport-security": "max-age=31536000" };
  const ids = idsOf(evidence);
  assert.equal(ids.get("hsts-enabled"), "info");
  assert.equal(ids.get("hsts-missing-includesubdomains"), "low");
});

test("server version disclosure and missing basics are info", () => {
  const evidence = baseEvidence();
  evidence.headers = { server: "nginx/1.25.3", "x-powered-by": "Express" };
  evidence.title = null;
  evidence.metaDescription = null;
  evidence.imagesMissingAlt = 3;
  evidence.imageTotal = 4;
  evidence.imageSample = ["logo.png"];
  const ids = idsOf(evidence);
  assert.equal(ids.get("server-version-disclosed"), "info");
  assert.equal(ids.get("title-missing"), "info");
  assert.equal(ids.get("meta-description-missing"), "info");
  assert.equal(ids.get("images-missing-alt"), "info");
});
