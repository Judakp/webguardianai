import test from "node:test";
import assert from "node:assert/strict";
import { analyzeWithPlaywright } from "./browserAnalyzer.js";

test("Playwright can be disabled without launching Chromium", async () => {
  const result = await analyzeWithPlaywright("https://example.com", { enabled: false });
  assert.equal(result.available, false);
  assert.equal(result.requestCount, 0);
  assert.match(result.reason ?? "", /disabled/i);
});

test("Playwright respects the environment disable switch", async () => {
  const previous = process.env.PLAYWRIGHT_ENABLED;
  process.env.PLAYWRIGHT_ENABLED = "false";
  try {
    const result = await analyzeWithPlaywright("https://example.com");
    assert.equal(result.available, false);
    assert.equal(result.requestCount, 0);
  } finally {
    if (previous === undefined) delete process.env.PLAYWRIGHT_ENABLED;
    else process.env.PLAYWRIGHT_ENABLED = previous;
  }
});
