import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import type { AddressInfo } from "node:net";
import { Zip, ZipDeflate, ZipPassThrough, strToU8 } from "fflate";
import { createApp } from "../app.js";
import { UPLOAD_DIR } from "./uploads.js";

// Deterministic PRNG so large fixtures are reproducible.
export function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Lowercase ASCII without NUL bytes: valid "source" that deflate cannot
// compress much, so `stored` entries keep their size on the wire.
export function randomTextChunk(size: number, seed = 1): Uint8Array {
  const rand = mulberry32(seed);
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i += 1) {
    out[i] = 97 + Math.floor(rand() * 26);
  }
  return out;
}

export interface StreamFileSpec {
  name: string;
  totalBytes: number;
  chunk: Uint8Array;
  stored?: boolean;
}

// Builds ZIPs via the streaming API (which uses data descriptors) without
// holding full plaintext in memory: `chunk` is pushed repeatedly.
export function makeStreamingZip(specs: StreamFileSpec[]): Uint8Array {
  const out: Uint8Array[] = [];
  const zip = new Zip((err, dat) => {
    assert.ifError(err);
    out.push(dat);
  });
  for (const spec of specs) {
    const file = spec.stored
      ? new ZipPassThrough(spec.name)
      : new ZipDeflate(spec.name, { level: 1 });
    zip.add(file);
    if (spec.totalBytes === 0) {
      file.push(new Uint8Array(0), true);
      continue;
    }
    let remaining = spec.totalBytes;
    while (remaining > 0) {
      const n = Math.min(remaining, spec.chunk.length);
      const piece = n === spec.chunk.length ? spec.chunk : spec.chunk.subarray(0, n);
      remaining -= n;
      file.push(piece, remaining === 0);
    }
  }
  zip.end();
  const total = out.reduce((n, c) => n + c.length, 0);
  assert.ok(total > 0, "streaming ZIP produced no output");
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of out) {
    joined.set(c, off);
    off += c.length;
  }
  return joined;
}

export function makeSmallStreamingZip(entries: Record<string, string>): Uint8Array {
  return makeStreamingZip(
    Object.entries(entries).map(([name, content]) => ({
      name,
      totalBytes: strToU8(content).length,
      chunk: strToU8(content),
    }))
  );
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;

// fflate emits no EOCD comment, so EOCD sits at length - 22.
export function eocdOffset(zip: Uint8Array): number {
  const eocd = zip.length - 22;
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  assert.equal(view.getUint32(eocd, true), EOCD_SIG, "expected EOCD at end of archive");
  return eocd;
}

export function patchEocd(zip: Uint8Array, fieldOffset: number, value: number, width: 2 | 4): Uint8Array {
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  const eocd = eocdOffset(out);
  if (width === 2) view.setUint16(eocd + fieldOffset, value, true);
  else view.setUint32(eocd + fieldOffset, value, true);
  return out;
}

export function patchAllUncompressedSizes(zip: Uint8Array, fakeSize: number): Uint8Array {
  const out = new Uint8Array(zip);
  const view = new DataView(out.buffer);
  const eocd = eocdOffset(out);
  const count = view.getUint16(eocd + 10, true);
  let pos = view.getUint32(eocd + 16, true);
  for (let n = 0; n < count; n += 1) {
    assert.equal(view.getUint32(pos, true), CD_SIG, "expected central-directory entry");
    view.setUint32(pos + 24, fakeSize, true);
    pos +=
      46 +
      view.getUint16(pos + 28, true) +
      view.getUint16(pos + 30, true) +
      view.getUint16(pos + 32, true);
  }
  return out;
}

export async function startTestServer(): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const app = createApp();
  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

export async function postProject(
  baseUrl: string,
  data: Uint8Array,
  filename = "project.zip",
  signal?: AbortSignal
): Promise<Response> {
  const form = new FormData();
  form.append("project", new Blob([data as BlobPart], { type: "application/zip" }), filename);
  return fetch(`${baseUrl}/api/offline/analyze`, { method: "POST", body: form, signal });
}

// Temp files owned by this process only; other parallel test processes are
// ignored so cleanup assertions stay deterministic.
export async function ownTempFiles(): Promise<string[]> {
  let entries: string[];
  try {
    entries = await fs.readdir(UPLOAD_DIR);
  } catch {
    return [];
  }
  return entries.filter((n) => n.startsWith(`upload-${process.pid}-`));
}

export async function pollUntil(
  predicate: () => Promise<boolean>,
  timeoutMs: number,
  label: string
): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (await predicate()) return;
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out waiting for: ${label}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}
