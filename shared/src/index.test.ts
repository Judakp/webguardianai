import test from "node:test";
import assert from "node:assert/strict";
import { createEmptyReport, summarizeFindings, REPORT_VERSION } from "./index.js";

test("createEmptyReport returns a versioned empty report", () => {
  const report = createEmptyReport("offline", "r1");
  assert.equal(report.version, REPORT_VERSION);
  assert.equal(report.mode, "offline");
  assert.equal(report.summary.total, 0);
  assert.deepEqual(report.findings, []);
});

test("summarizeFindings counts severities", () => {
  const summary = summarizeFindings([
    { id: "a", title: "t", severity: "high" },
    { id: "b", title: "t", severity: "low" },
    { id: "c", title: "t", severity: "low" },
  ]);
  assert.equal(summary.total, 3);
  assert.equal(summary.bySeverity.high, 1);
  assert.equal(summary.bySeverity.low, 2);
});
