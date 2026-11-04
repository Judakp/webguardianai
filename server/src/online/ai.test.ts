import test from "node:test";
import assert from "node:assert/strict";
import { analyzeWithMuseSpark, aiEngineFinding } from "./ai.js";
import type { SiteEvidence } from "./extract.js";

const evidence: SiteEvidence = {
  startUrl: "https://example.com/",
  finalUrl: "https://example.com/",
  finalIsHttps: true,
  status: 200,
  headers: { "content-security-policy": "default-src 'self'" },
  setCookies: [],
  redirectHops: 0,
  title: "Example",
  metaDescription: null,
  metaCount: 1,
  canonical: null,
  robotsMeta: null,
  htmlLang: "en",
  headings: [{ level: 1, text: "Welcome" }],
  headingTotal: 1,
  h1Count: 1,
  headingSkips: [],
  internalLinkTotal: 0,
  externalLinkTotal: 0,
  suspiciousLinks: [],
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
  cssSample: [],
};

test("Muse Spark integration uses structured output and normalizes findings", async () => {
  let requestBody: any;
  const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
    requestBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        choices: [
          {
            message: {
              content: JSON.stringify({
                findings: [
                  {
                    severity: "medium",
                    category: "SEO",
                    title: "The page lacks a meta description",
                    description: "No meta description was observed in the extracted head metadata.",
                    whyItMatters: "Search engines may have less useful text available for result snippets.",
                    confidence: "high",
                    evidence: "metaDescription: null",
                    recommendation: "Add a concise, page-specific meta description.",
                  },
                ],
              }),
            },
          },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  }) as unknown as typeof fetch;

  const result = await analyzeWithMuseSpark(evidence, [], {
    apiKey: "test-key",
    fetchImpl,
    baseUrl: "https://api.meta.ai/v1",
    model: "muse-spark-1.3",
    timeoutMs: 1000,
  });

  assert.equal(result.available, true);
  assert.equal(result.model, "muse-spark-1.3");
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0]!.id, /^ai-/);
  assert.equal(requestBody.model, "muse-spark-1.3");
  assert.equal(requestBody.response_format.type, "json_schema");
  assert.equal(requestBody.messages[0].role, "developer");
  assert.match(requestBody.messages[0].content, /untrusted website data/i);
});

test("missing API key leaves the deterministic engine available", async () => {
  const result = await analyzeWithMuseSpark(evidence, [], { apiKey: "" });
  assert.equal(result.available, false);
  assert.deepEqual(result.findings, []);
  assert.match(result.reason ?? "", /MODEL_API_KEY/);
  assert.equal(aiEngineFinding("muse-spark-1.3").severity, "info");
});
