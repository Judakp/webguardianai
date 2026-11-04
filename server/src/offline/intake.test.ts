import test from "node:test";
import assert from "node:assert/strict";
import { TextEncoder } from "node:util";
import { zipSync, strToU8 } from "fflate";
import {
  extractZipSafely,
  IntakeError,
  MAX_ARCHIVE_BYTES,
  MAX_EXTRACTED_BYTES,
  MAX_FILES,
  MAX_FILE_BYTES,
  normalizeEntryName,
} from "./intake.js";
import {
  eocdOffset,
  makeSmallStreamingZip,
  patchEocd,
} from "./testHelpers.js";

function makeZip(entries: Record<string, string | Uint8Array>): Uint8Array {
  const input: Record<string, Uint8Array> = {};
  for (const [name, value] of Object.entries(entries)) {
    input[name] = typeof value === "string" ? strToU8(value) : value;
  }
  return zipSync(input);
}

// Rewrites one central-directory uncompressed-size field so tests can
// simulate lying or bomb-like archives without allocating huge buffers.
function patchCentralDirectorySize(
  zip: Uint8Array,
  fileName: string,
  fakeSize: number
): Uint8Array {
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  const nameBytes = new TextEncoder().encode(fileName);
  let idx = -1;
  outer: for (let i = out.length - nameBytes.length; i >= 0; i -= 1) {
    for (let j = 0; j < nameBytes.length; j += 1) {
      if (out[i + j] !== nameBytes[j]) continue outer;
    }
    idx = i;
    break;
  }
  assert.notEqual(idx, -1, "file name not found in archive bytes");
  const cdStart = idx - 46;
  assert.equal(view.getUint32(cdStart, true), 0x02014b50, "not a central-directory entry");
  view.setUint32(cdStart + 24, fakeSize, true);
  return out;
}

test("accepts a valid project ZIP with languages and manifests", () => {
  const zip = makeZip({
    "index.html": "<html></html>",
    "src/app.js": "console.log(1)",
    "package.json": '{"name":"demo"}',
  });
  const inventory = extractZipSafely(zip);
  assert.equal(inventory.files.length, 3);
  assert.deepEqual(
    inventory.files.map((f) => [f.path, f.language, f.manifest]),
    [
      ["index.html", "html", false],
      ["package.json", "unknown", true],
      ["src/app.js", "javascript", false],
    ]
  );
  assert.deepEqual(inventory.skipped, []);
});

test("maps all supported extensions to languages", () => {
  const zip = makeZip({
    "a.css": "x",
    "a.js": "x",
    "a.mjs": "x",
    "a.cjs": "x",
    "a.ts": "x",
    "a.jsx": "x",
    "a.tsx": "x",
    "a.php": "x",
    "a.py": "x",
    "a.htm": "x",
    "composer.json": "{}",
  });
  const inventory = extractZipSafely(zip);
  const byPath = new Map(inventory.files.map((f) => [f.path, f.language]));
  assert.equal(byPath.get("a.css"), "css");
  assert.equal(byPath.get("a.js"), "javascript");
  assert.equal(byPath.get("a.mjs"), "javascript");
  assert.equal(byPath.get("a.cjs"), "javascript");
  assert.equal(byPath.get("a.ts"), "typescript");
  assert.equal(byPath.get("a.jsx"), "jsx");
  assert.equal(byPath.get("a.tsx"), "tsx");
  assert.equal(byPath.get("a.php"), "php");
  assert.equal(byPath.get("a.py"), "python");
  assert.equal(byPath.get("a.htm"), "html");
  assert.equal(byPath.get("composer.json"), "unknown");
});

test("rejects traversal and absolute entry names", () => {
  assert.equal(normalizeEntryName("../evil.js"), null);
  assert.equal(normalizeEntryName("a/../../evil.js"), null);
  assert.equal(normalizeEntryName("/abs.js"), null);
  assert.equal(normalizeEntryName("C:/win.js"), null);
  assert.equal(normalizeEntryName("C:\\win.js"), null);
  assert.equal(normalizeEntryName("a/./b.js"), null);
  assert.equal(normalizeEntryName("ok/nested.js"), "ok/nested.js");

  const zip = makeZip({
    "../evil.js": "x",
    "/abs.js": "x",
    "fine.js": "x",
  });
  const inventory = extractZipSafely(zip);
  assert.deepEqual(
    inventory.files.map((f) => f.path),
    ["fine.js"]
  );
  assert.ok(inventory.skipped.every((s) => s.reason === "unsafe-path"));
  assert.equal(inventory.skipped.length, 2);
});

test("rejects oversized archives before decompressing", () => {
  const big = new Uint8Array(MAX_ARCHIVE_BYTES + 1);
  assert.throws(() => extractZipSafely(big), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "too-large");
    assert.equal(err.status, 413);
    return true;
  });
});

test("rejects archives declaring too many files", () => {
  const entries: Record<string, Uint8Array> = {};
  for (let i = 0; i < MAX_FILES + 1; i += 1) {
    entries[`f${i}.js`] = strToU8("x");
  }
  const zip = makeZip(entries);
  assert.throws(() => extractZipSafely(zip), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "too-many-files");
    return true;
  });
});

test("precheck rejects bomb-like size claims without allocating", () => {
  const zip = makeZip({ "payload.js": "console.log(1)" });
  const bomb = patchCentralDirectorySize(zip, "payload.js", MAX_EXTRACTED_BYTES + 1);
  assert.throws(() => extractZipSafely(bomb), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "extracted-too-large");
    assert.equal(err.status, 413);
    return true;
  });
});

test("rejects archives containing an over-limit file", () => {
  const content = "x".repeat(MAX_FILE_BYTES + 1);
  const zip = makeZip({ "big.js": content, "small.js": "ok" });
  assert.throws(() => extractZipSafely(zip), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "extracted-too-large");
    assert.equal(err.status, 413);
    assert.ok(err.message.includes("big.js"));
    return true;
  });
});

test("lying-small size claims stay bounded and never crash intake", () => {
  const zip = makeZip({ "big.js": "console.log(1)" });
  const lying = patchCentralDirectorySize(zip, "big.js", 10);
  const inventory = extractZipSafely(lying);
  assert.ok(inventory.extractedBytes <= MAX_FILE_BYTES);
  assert.ok(inventory.files.length + inventory.skipped.length <= MAX_FILES);
});

test("skips disallowed extensions, binaries and dotfiles", () => {
  const binary = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01]);
  const zip = makeZip({
    "img.png": binary,
    "bad.js": binary,
    "doc.pdf": "pdf?",
    ".gitignore": "x",
    "Dockerfile": "x",
    "ok.py": "print(1)",
  });
  const inventory = extractZipSafely(zip);
  assert.deepEqual(
    inventory.files.map((f) => f.path),
    ["ok.py"]
  );
  const reasons = new Map(inventory.skipped.map((s) => [s.path, s.reason]));
  assert.equal(reasons.get("img.png"), "extension");
  assert.equal(reasons.get("bad.js"), "binary");
  assert.equal(reasons.get("doc.pdf"), "extension");
  assert.equal(reasons.get(".gitignore"), "extension");
  assert.equal(reasons.get("Dockerfile"), "extension");
});

test("rejects non-ZIP input", () => {
  assert.throws(() => extractZipSafely(strToU8("hello, not a zip")), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "not-a-zip");
    assert.equal(err.status, 400);
    return true;
  });
});

test("accepts an empty archive as an empty inventory", () => {
  const inventory = extractZipSafely(zipSync({}));
  assert.deepEqual(inventory.files, []);
  assert.deepEqual(inventory.skipped, []);
});

// Rewrites a 2-byte central-directory field so tests can simulate
// unsupported methods or encryption flags without real fixtures.
function patchCdEntryField(zip: Uint8Array, fileName: string, fieldOffset: number, value: number): Uint8Array {
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  const nameBytes = new TextEncoder().encode(fileName);
  let idx = -1;
  outer: for (let i = out.length - nameBytes.length; i >= 0; i -= 1) {
    for (let j = 0; j < nameBytes.length; j += 1) {
      if (out[i + j] !== nameBytes[j]) continue outer;
    }
    idx = i;
    break;
  }
  assert.notEqual(idx, -1, "file name not found in archive bytes");
  const cdStart = idx - 46;
  assert.equal(view.getUint32(cdStart, true), 0x02014b50, "not a central-directory entry");
  view.setUint16(cdStart + fieldOffset, value, true);
  return out;
}

test("excludes generated directories without over-excluding", () => {
  const zip = makeZip({
    "node_modules/dep/index.js": "x",
    "src/app.js": "x",
    "vendor/lib.php": "x",
    "dist/bundle.js": "x",
    "build/out.js": "x",
    ".next/static.js": "x",
    ".git/hooks.js": "x",
    "coverage/lcov.js": "x",
    "coverage.js": "x",
    "my-dist/app.js": "x",
    "src/node_modules/nested.js": "x",
    "package.json": "{}",
    "node_modules/dep/package.json": "{}",
  });
  const inventory = extractZipSafely(zip);
  assert.deepEqual(
    inventory.files.map((f) => f.path),
    ["coverage.js", "my-dist/app.js", "package.json", "src/app.js"]
  );
  const reasons = new Map(inventory.skipped.map((s) => [s.path, s.reason]));
  for (const p of [
    "node_modules/dep/index.js",
    "vendor/lib.php",
    "dist/bundle.js",
    "build/out.js",
    ".next/static.js",
    ".git/hooks.js",
    "coverage/lcov.js",
    "src/node_modules/nested.js",
    "node_modules/dep/package.json",
  ]) {
    assert.equal(reasons.get(p), "excluded", p);
  }
  assert.equal(inventory.skipped.length, 9);
});

test("accepts a file exactly at the per-file limit", () => {
  const inventory = extractZipSafely(makeZip({ "edge.js": "a".repeat(MAX_FILE_BYTES) }));
  assert.equal(inventory.files.length, 1);
  assert.equal(inventory.files[0]!.size, MAX_FILE_BYTES);
});

test("streaming enforcement stops a lying-small decompression bomb", () => {
  const zip = makeZip({ "bomb.js": "a".repeat(MAX_FILE_BYTES + 1024) });
  const lying = patchCentralDirectorySize(zip, "bomb.js", 16);
  assert.throws(() => extractZipSafely(lying), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "extracted-too-large");
    assert.equal(err.status, 413);
    assert.ok(err.message.includes("bomb.js"));
    return true;
  });
});

test("rejects zip64 end-of-central-directory placeholders", () => {
  const zip = makeZip({ "a.js": "x" });
  assert.throws(() => extractZipSafely(patchEocd(zip, 10, 0xffff, 2)), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "unsupported-format");
    assert.equal(err.status, 400);
    return true;
  });
});

test("rejects zip64 size placeholders in entries", () => {
  const zip = makeZip({ "a.js": "x" });
  const zip64 = patchCentralDirectorySize(zip, "a.js", 0xffffffff);
  assert.throws(() => extractZipSafely(zip64), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "unsupported-format");
    return true;
  });
});

test("rejects unsupported compression methods", () => {
  const zip = makeZip({ "a.js": "x" });
  const lzma = patchCdEntryField(zip, "a.js", 10, 14);
  assert.throws(() => extractZipSafely(lzma), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "unsupported-format");
    return true;
  });
});

test("rejects encrypted entries", () => {
  const zip = makeZip({ "a.js": "x" });
  const out = new Uint8Array(zip);
  const outView = new DataView(out.buffer);
  const nameBytes = new TextEncoder().encode("a.js");
  let idx = -1;
  outer: for (let i = out.length - nameBytes.length; i >= 0; i -= 1) {
    for (let j = 0; j < nameBytes.length; j += 1) {
      if (out[i + j] !== nameBytes[j]) continue outer;
    }
    idx = i;
    break;
  }
  const cdStart = idx - 46;
  outView.setUint16(cdStart + 8, outView.getUint16(cdStart + 8, true) | 0x1, true);
  assert.throws(() => extractZipSafely(out), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "unsupported-format");
    return true;
  });
});

test("rejects multi-disk archives", () => {
  const zip = makeZip({ "a.js": "x" });
  assert.throws(() => extractZipSafely(patchEocd(zip, 4, 1, 2)), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "unsupported-format");
    return true;
  });
});

test("rejects truncated archives", () => {
  const zip = makeZip({ "a.js": "console.log(1);".repeat(200) });
  assert.throws(() => extractZipSafely(zip.subarray(0, zip.length - 8)), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "not-a-zip");
    return true;
  });
});

test("rejects central directories with corrupt signatures", () => {
  const zip = makeZip({ "a.js": "x" });
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  const eocd = eocdOffset(out);
  const cdOff = view.getUint32(eocd + 16, true);
  out[cdOff] ^= 0xff;
  assert.throws(() => extractZipSafely(out), (err: unknown) => {
    assert.ok(err instanceof IntakeError);
    assert.equal(err.code, "not-a-zip");
    return true;
  });
});

test("rejects central directories pointing outside the archive", () => {
  const zip = makeZip({ "a.js": "x" });
  assert.throws(
    () => extractZipSafely(patchEocd(zip, 16, 0xffffff00, 4)),
    (err: unknown) => {
      assert.ok(err instanceof IntakeError);
      assert.equal(err.code, "not-a-zip");
      return true;
    }
  );
});

test("supports archives using data descriptors", () => {
  const zip = makeSmallStreamingZip({ "a.js": "console.log(1)", "src/b.py": "print(1)" });
  const flags = new DataView(zip.buffer, zip.byteOffset, zip.byteLength).getUint16(6, true);
  assert.ok((flags & 8) !== 0, "fixture must use a data descriptor");
  const inventory = extractZipSafely(zip);
  assert.deepEqual(
    inventory.files.map((f) => f.path),
    ["a.js", "src/b.py"]
  );
});

test("accepts archives with an end-of-central-directory comment", () => {
  const zip = makeZip({ "a.js": "x" });
  const comment = strToU8("hello-comment");
  const out = new Uint8Array(zip.length + comment.length);
  out.set(zip, 0);
  out.set(comment, zip.length);
  new DataView(out.buffer).setUint16(zip.length - 22 + 20, comment.length, true);
  const inventory = extractZipSafely(out);
  assert.equal(inventory.files.length, 1);
  assert.equal(inventory.files[0]!.path, "a.js");
});

test("skips directory entries without inflating them", () => {
  const zip = makeZip({ "dir/": new Uint8Array(0), "dir/a.js": "x" });
  const inventory = extractZipSafely(zip);
  assert.deepEqual(
    inventory.files.map((f) => f.path),
    ["dir/a.js"]
  );
  assert.deepEqual(inventory.skipped, []);
});
