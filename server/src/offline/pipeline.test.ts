import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { zipSync, strToU8 } from "fflate";
import {
  MAX_ARCHIVE_BYTES,
  MAX_EXTRACTED_BYTES,
  MAX_FILES,
  MAX_FILE_BYTES,
} from "./intake.js";
import {
  UPLOAD_DIR,
  ensureUploadDir,
  getActiveAnalyses,
  getMaxConcurrentAnalyses,
  releaseAnalysisSlot,
  tryAcquireAnalysisSlot,
} from "./uploads.js";
import {
  runExtractionInWorker,
  WorkerTimeoutError,
} from "./workerClient.js";
import {
  makeSmallStreamingZip,
  makeStreamingZip,
  ownTempFiles,
  patchAllUncompressedSizes,
  pollUntil,
  postProject,
  randomTextChunk,
  startTestServer,
} from "./testHelpers.js";

function makeZip(entries: Record<string, string | Uint8Array>): Uint8Array {
  const input: Record<string, Uint8Array> = {};
  for (const [name, value] of Object.entries(entries)) {
    input[name] = typeof value === "string" ? strToU8(value) : value;
  }
  return zipSync(input);
}

interface ApiInventory {
  files: Array<{ path: string; size: number; language: string; manifest: boolean }>;
  skipped: Array<{ path: string; reason: string }>;
  archiveBytes: number;
  extractedBytes: number;
}

async function readJson(res: Response): Promise<{ ok: boolean; inventory?: ApiInventory; error?: string; code?: string }> {
  return (await res.json()) as {
    ok: boolean;
    inventory?: ApiInventory;
    error?: string;
    code?: string;
  };
}

test("upload pipeline analyzes a project and cleans up", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const zip = makeZip({
      "index.html": "<html></html>",
      "src/app.js": "console.log(1)",
      "package.json": '{"name":"demo"}',
    });
    const res = await postProject(baseUrl, zip);
    assert.equal(res.status, 200);
    const body = await readJson(res);
    assert.equal(body.ok, true);
    assert.deepEqual(
      body.inventory!.files.map((f) => f.path),
      ["index.html", "package.json", "src/app.js"]
    );
    assert.ok(!("content" in body.inventory!.files[0]!), "public files must not carry contents");
    assert.deepEqual(body.inventory!.skipped, []);
    assert.equal(body.inventory!.archiveBytes, zip.byteLength);
    assert.deepEqual(await ownTempFiles(), []);
    assert.equal(getActiveAnalyses(), 0);
  } finally {
    await close();
  }
});

test("upload pipeline reports traversal entries as skipped", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const res = await postProject(
      baseUrl,
      makeZip({ "../evil.js": "x", "/abs.js": "x", "fine.js": "x" })
    );
    assert.equal(res.status, 200);
    const body = await readJson(res);
    assert.deepEqual(
      body.inventory!.files.map((f) => f.path),
      ["fine.js"]
    );
    assert.deepEqual(
      body.inventory!.skipped.map((s) => s.reason),
      ["unsafe-path", "unsafe-path"]
    );
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test("upload pipeline rejects bomb-like size claims", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const zip = makeZip({ "payload.js": "console.log(1)" });
    const bomb = patchAllUncompressedSizes(zip, MAX_EXTRACTED_BYTES + 1);
    const res = await postProject(baseUrl, bomb);
    assert.equal(res.status, 413);
    const body = await readJson(res);
    assert.equal(body.code, "extracted-too-large");
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test(
  "streaming totals stop a lying-small bomb before unbounded allocation",
  { timeout: 300_000 },
  async () => {
    const { baseUrl, close } = await startTestServer();
    try {
      const chunk = new Uint8Array(1024 * 1024).fill(97);
      const specs = Array.from({ length: 40 }, (_, i) => ({
        name: `f${i}.js`,
        totalBytes: 8 * 1024 * 1024,
        chunk,
      }));
      const zip = makeStreamingZip(specs);
      assert.ok(zip.byteLength < 1024 * 1024, "bomb fixture must stay small on the wire");
      const lying = patchAllUncompressedSizes(zip, 10);
      const before = process.memoryUsage().rss;
      const res = await postProject(baseUrl, lying);
      assert.equal(res.status, 413);
      const body = await readJson(res);
      assert.equal(body.code, "extracted-too-large");
      const growth = process.memoryUsage().rss - before;
      assert.ok(growth < MAX_EXTRACTED_BYTES, `rss grew by ${growth} bytes`);
      assert.deepEqual(await ownTempFiles(), []);
    } finally {
      await close();
    }
  }
);

test("upload pipeline rejects per-file actual over-limit", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const zip = makeStreamingZip([
      { name: "big.js", totalBytes: MAX_FILE_BYTES + 1024, chunk: new Uint8Array(65536).fill(98) },
    ]);
    const lying = patchAllUncompressedSizes(zip, 10);
    const res = await postProject(baseUrl, lying);
    assert.equal(res.status, 413);
    const body = await readJson(res);
    assert.equal(body.code, "extracted-too-large");
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test("upload pipeline rejects too many files", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const entries: Record<string, Uint8Array> = {};
    for (let i = 0; i < MAX_FILES + 1; i += 1) entries[`f${i}.js`] = strToU8("x");
    const res = await postProject(baseUrl, zipSync(entries));
    assert.equal(res.status, 400);
    const body = await readJson(res);
    assert.equal(body.code, "too-many-files");
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test(
  "accepts a valid archive near the 100 MiB compressed limit",
  { timeout: 300_000 },
  async () => {
    const { baseUrl, close } = await startTestServer();
    try {
      const chunk = randomTextChunk(1024 * 1024, 7);
      // Stored entries keep their size on the wire, so leave headroom for
      // ZIP headers and the central directory (~1 KiB for 10 files).
      const fileBytes = 10 * 1024 * 1024 - 2048;
      const specs = Array.from({ length: 10 }, (_, i) => ({
        name: `big${i}.js`,
        totalBytes: fileBytes,
        chunk,
        stored: true,
      }));
      const zip = makeStreamingZip(specs);
      assert.ok(zip.byteLength > 95 * 1024 * 1024, `fixture is ${zip.byteLength} bytes`);
      assert.ok(zip.byteLength <= MAX_ARCHIVE_BYTES, `fixture is ${zip.byteLength} bytes`);
      const res = await postProject(baseUrl, zip, "hundred.zip");
      assert.equal(res.status, 200);
      const body = await readJson(res);
      assert.equal(body.inventory!.files.length, 10);
      assert.ok(body.inventory!.files.every((f) => f.size === fileBytes));
      assert.equal(body.inventory!.extractedBytes, 10 * fileBytes);
      assert.deepEqual(await ownTempFiles(), []);
    } finally {
      await close();
    }
  }
);

test(
  "accepts a valid archive near the 300 MiB extracted limit",
  { timeout: 300_000 },
  async () => {
    const { baseUrl, close } = await startTestServer();
    try {
      const chunk = new Uint8Array(1024 * 1024).fill(97);
      const specs = Array.from({ length: 30 }, (_, i) => ({
        name: `bulk${i}.js`,
        totalBytes: 10 * 1024 * 1024,
        chunk,
      }));
      const zip = makeStreamingZip(specs);
      assert.ok(zip.byteLength < 2 * 1024 * 1024, `fixture is ${zip.byteLength} bytes`);
      const res = await postProject(baseUrl, zip, "bulk.zip");
      assert.equal(res.status, 200);
      const body = await readJson(res);
      assert.equal(body.inventory!.files.length, 30);
      assert.equal(body.inventory!.extractedBytes, MAX_EXTRACTED_BYTES);
      assert.deepEqual(await ownTempFiles(), []);
    } finally {
      await close();
    }
  }
);

test("rejects archives extracting beyond the total limit", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const chunk = new Uint8Array(65536).fill(99);
    const specs = Array.from({ length: 30 }, (_, i) => ({
      name: `bulk${i}.js`,
      totalBytes: 10 * 1024 * 1024,
      chunk,
    }));
    specs.push({ name: "one-more.js", totalBytes: 1, chunk });
    const res = await postProject(baseUrl, makeStreamingZip(specs));
    assert.equal(res.status, 413);
    const body = await readJson(res);
    assert.equal(body.code, "extracted-too-large");
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test("upload pipeline rejects non-ZIP uploads", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const res = await postProject(baseUrl, strToU8("hello, not a zip"), "note.txt");
    assert.equal(res.status, 400);
    const body = await readJson(res);
    assert.equal(body.code, "not-a-zip");
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test("upload pipeline rejects oversized archives", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const over = new Uint8Array(MAX_ARCHIVE_BYTES + 65536);
    const res = await postProject(baseUrl, over, "huge.bin");
    assert.equal(res.status, 413);
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test("upload pipeline rejects a missing file field", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const form = new FormData();
    form.append("wrong", new Blob(["x"]), "x.zip");
    const res = await fetch(`${baseUrl}/api/offline/analyze`, { method: "POST", body: form });
    assert.equal(res.status, 400);
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    await close();
  }
});

test("upload pipeline returns 429 when all slots are busy", async () => {
  const { baseUrl, close } = await startTestServer();
  const max = getMaxConcurrentAnalyses();
  for (let i = 0; i < max; i += 1) assert.equal(tryAcquireAnalysisSlot(), true);
  try {
    const res = await postProject(baseUrl, makeZip({ "a.js": "x" }));
    assert.equal(res.status, 429);
    const body = await readJson(res);
    assert.equal(body.code, "busy");
    assert.deepEqual(await ownTempFiles(), []);
  } finally {
    for (let i = 0; i < max; i += 1) releaseAnalysisSlot();
    await close();
  }
});

test("worker runs time out instead of hanging", async () => {
  await ensureUploadDir();
  const filePath = path.join(UPLOAD_DIR, `timeout-probe-${Date.now()}.zip`);
  try {
    await fs.writeFile(filePath, makeSmallStreamingZip({ "a.js": "x" }));
    await assert.rejects(
      runExtractionInWorker(filePath, { timeoutMs: 1 }),
      (err: unknown) => {
        assert.ok(err instanceof WorkerTimeoutError);
        return true;
      }
    );
  } finally {
    await fs.rm(filePath, { force: true });
  }
});

test("worker reports missing uploads without crashing", async () => {
  const outcome = await runExtractionInWorker(
    path.join(os.tmpdir(), `webguardian-nope-${Date.now()}.zip`),
    { timeoutMs: 10_000 }
  );
  assert.equal(outcome.ok, false);
  if (!outcome.ok) {
    assert.equal(outcome.code, "not-a-zip");
    assert.equal(outcome.status, 400);
  }
});

test("client disconnects clean up temp uploads", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const chunk = randomTextChunk(1024 * 1024, 11);
    const zip = makeStreamingZip([
      { name: "a.js", totalBytes: 30 * 1024 * 1024, chunk, stored: true },
    ]);
    const controller = new AbortController();
    const pending = postProject(baseUrl, zip, "abort.zip", controller.signal);
    setTimeout(() => controller.abort(), 50);
    await assert.rejects(pending);
    await pollUntil(async () => (await ownTempFiles()).length === 0, 15_000, "temp cleanup");
    await pollUntil(async () => getActiveAnalyses() === 0, 15_000, "slot release");
  } finally {
    await close();
  }
});

test(
  "server stays responsive during large extraction",
  { timeout: 300_000 },
  async () => {
    const { baseUrl, close } = await startTestServer();
    try {
      const chunk = new Uint8Array(1024 * 1024).fill(100);
      const specs = Array.from({ length: 20 }, (_, i) => ({
        name: `w${i}.js`,
        totalBytes: 10 * 1024 * 1024,
        chunk,
      }));
      const zip = makeStreamingZip(specs);
      const pending = postProject(baseUrl, zip, "heavy.zip");
      const start = Date.now();
      const health = await fetch(`${baseUrl}/api/health`);
      const latencyMs = Date.now() - start;
      assert.equal(health.status, 200);
      assert.ok(latencyMs < 10_000, `health latency was ${latencyMs}ms`);
      const res = await pending;
      assert.equal(res.status, 200);
      assert.deepEqual(await ownTempFiles(), []);
    } finally {
      await close();
    }
  }
);
