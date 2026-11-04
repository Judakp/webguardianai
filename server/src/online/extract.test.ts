import test from "node:test";
import assert from "node:assert/strict";
import { extractEvidence } from "./extract.js";
import type { FetchedSite } from "./fetchSite.js";

// Synthetic fixture (hand-written for parser tests, not a real page).
const FIXTURE = `<!doctype html>
<html><head>
<title>Example &amp; Demo</title>
<meta name="description" content="A demo page">
<meta property="og:title" content="Demo">
<!-- <a href="https://comment.example/hidden">not a link</a> -->
<script src="https://cdn.example/lib.js" async></script>
<script>var s = "<a href=\\"https://js.example/fake\\">fake</a>";</script>
<script src="/local.js" defer integrity="sha384-abc"></script>
<link rel="stylesheet" href="https://cdn.example/app.css">
<link rel="stylesheet" href="http://cdn.example/old.css">
</head><body>
<h1>Main Heading</h1>
<h2>Sub <em>heading</em></h2>
<a href="/internal">Internal</a>
<a href="https://external.example/page" target="_blank">External</a>
<a href="https://safe.example/x" target="_blank" rel="noopener">Safe</a>
<a href="javascript:void(0)">JS link</a>
<form action="https://example.com/login" method="post">
<input type="text" name="u"><input type="password" name="p">
</form>
<form action="http://example.com/search"><input type="text" name="q"></form>
<img src="a.png" alt="A"><img src="b.png"><img src="c.png" alt="">
<button onclick="doThing()">Click</button>
</body></html>`;

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

test("extracts title, meta, and headings", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  assert.equal(evidence.title, "Example & Demo");
  assert.equal(evidence.metaDescription, "A demo page");
  assert.ok(evidence.metaCount >= 2);
  assert.deepEqual(
    evidence.headings.map((h) => [h.level, h.text]),
    [
      [1, "Main Heading"],
      [2, "Sub heading"],
    ]
  );
  assert.equal(evidence.headingTotal, 2);
});

test("ignores markup inside comments and script bodies", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  assert.ok(
    evidence.links.every((l) => !l.href.includes("comment.example") && !l.href.includes("js.example")),
    JSON.stringify(evidence.links.map((l) => l.href))
  );
});

test("classifies links, blank targets, and javascript hrefs", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  const byHref = new Map(evidence.links.map((l) => [l.href, l]));
  assert.equal(byHref.get("https://example.com/internal")?.external, false);
  assert.equal(byHref.get("https://external.example/page")?.external, true);
  assert.equal(byHref.get("https://external.example/page")?.targetBlank, true);
  assert.equal(byHref.get("https://external.example/page")?.rel, "");
  assert.equal(byHref.get("https://safe.example/x")?.rel, "noopener");
  assert.equal(evidence.jsHrefCount, 1);
  assert.deepEqual(evidence.jsHrefSample, ["javascript:void(0)"]);
});

test("records scripts with async, defer, and integrity", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  assert.equal(evidence.scriptTotal, 3);
  assert.equal(evidence.inlineScriptCount, 1);
  const cdn = evidence.scripts.find((s) => s.src === "https://cdn.example/lib.js");
  assert.equal(cdn?.async, true);
  assert.equal(cdn?.external, true);
  assert.equal(cdn?.integrity, false);
  const local = evidence.scripts.find((s) => s.src === "https://example.com/local.js");
  assert.equal(local?.defer, true);
  assert.equal(local?.integrity, true);
  assert.equal(local?.external, false);
});

test("records forms with password fields and action schemes", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  assert.equal(evidence.formTotal, 2);
  const login = evidence.forms.find((f) => f.hasPassword);
  assert.equal(login?.http, false);
  assert.equal(login?.method, "post");
  const search = evidence.forms.find((f) => !f.hasPassword);
  assert.equal(search?.http, true);
});

test("counts images missing alt and inline handlers", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  assert.equal(evidence.imageTotal, 3);
  assert.equal(evidence.imagesMissingAlt, 2);
  assert.equal(evidence.inlineHandlerCount, 1);
  assert.ok(evidence.inlineHandlerSample[0]!.includes("<button>"));
});

test("collects http subresources for mixed-content checks", () => {
  const evidence = extractEvidence(fetched(FIXTURE));
  assert.ok(evidence.subresourceHttp.includes("http://cdn.example/old.css"));
  assert.equal(evidence.stylesheetTotal, 2);
});

test("empty page yields empty evidence without crashing", () => {
  const evidence = extractEvidence(fetched(""));
  assert.equal(evidence.title, null);
  assert.equal(evidence.metaDescription, null);
  assert.equal(evidence.links.length, 0);
  assert.equal(evidence.forms.length, 0);
});
