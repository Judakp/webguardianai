import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import {
  UPLOAD_DIR,
  ensureUploadDir,
  getActiveAnalyses,
  getMaxConcurrentAnalyses,
  releaseAnalysisSlot,
  sweepOrphanUploads,
  tryAcquireAnalysisSlot,
} from "./uploads.js";

test("analysis slots enforce the concurrency limit", () => {
  const max = getMaxConcurrentAnalyses();
  assert.ok(max >= 1);
  assert.equal(getActiveAnalyses(), 0);
  for (let i = 0; i < max; i += 1) assert.equal(tryAcquireAnalysisSlot(), true);
  assert.equal(tryAcquireAnalysisSlot(), false);
  for (let i = 0; i < max; i += 1) releaseAnalysisSlot();
  assert.equal(getActiveAnalyses(), 0);
  releaseAnalysisSlot();
  assert.equal(getActiveAnalyses(), 0);
});

test("orphan sweep deletes dead uploads and keeps live ones", async () => {
  await ensureUploadDir();
  const tag = randomUUID();
  const deadPid = `upload-99999999-${tag}-a.zip`;
  const aged = `upload-${process.pid}-${tag}-b.zip`;
  const fresh = `upload-${process.pid}-${tag}-c.zip`;
  const foreign = `foreign-${tag}.txt`;
  await fs.writeFile(path.join(UPLOAD_DIR, deadPid), "x");
  await fs.writeFile(path.join(UPLOAD_DIR, aged), "x");
  await fs.writeFile(path.join(UPLOAD_DIR, fresh), "x");
  await fs.writeFile(path.join(UPLOAD_DIR, foreign), "x");
  const ancient = new Date(Date.now() - 2 * 3_600_000);
  await fs.utimes(path.join(UPLOAD_DIR, aged), ancient, ancient);

  const result = await sweepOrphanUploads();
  assert.ok(result.deleted >= 1, "expected at least the dead-pid orphan to be reaped");

  const remaining = await fs.readdir(UPLOAD_DIR);
  assert.ok(!remaining.includes(deadPid), "dead-pid orphan must be deleted");
  assert.ok(!remaining.includes(aged), "aged upload must be deleted");
  assert.ok(remaining.includes(fresh), "fresh upload must be kept");
  assert.ok(remaining.includes(foreign), "foreign files must be kept");

  await fs.unlink(path.join(UPLOAD_DIR, fresh));
  await fs.unlink(path.join(UPLOAD_DIR, foreign));
});
