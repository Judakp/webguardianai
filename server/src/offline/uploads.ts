import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import multer from "multer";
import {
  MAX_ARCHIVE_BYTES,
  MAX_CONCURRENT_ANALYSES,
  ORPHAN_MAX_AGE_MS,
  ORPHAN_SWEEP_INTERVAL_MS,
} from "./limits.js";

// Overridable for containers, read-only system temp dirs, and disk quotas.
// Defaults to the OS temp dir; tests point it at a writable scratch root.
export const UPLOAD_DIR =
  process.env.WEBGUARDIAN_UPLOAD_DIR ?? path.join(os.tmpdir(), "webguardian-uploads");
export const UPLOAD_FIELD = "project";
const FILENAME_PREFIX = "upload-";

export async function ensureUploadDir(): Promise<void> {
  await fs.mkdir(UPLOAD_DIR, { recursive: true, mode: 0o700 });
}

function tempName(): string {
  return `${FILENAME_PREFIX}${process.pid}-${randomUUID()}.zip`;
}

// Disk-backed intake: the upload streams straight to a temp file so a 100 MiB
// archive never sits in the main-thread heap. Multer enforces the size cap
// while writing; the handler re-checks with stat before analysis.
export const multerUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => {
      ensureUploadDir().then(
        () => cb(null, UPLOAD_DIR),
        (err: unknown) => cb(err as Error, "")
      );
    },
    filename: (req, _file, cb) => {
      const name = tempName();
      (req as unknown as Record<string, unknown>)._uploadTempPath = path.join(
        UPLOAD_DIR,
        name
      );
      cb(null, name);
    },
  }),
  limits: { fileSize: MAX_ARCHIVE_BYTES, files: 1 },
});

export function getRequestTempPath(req: unknown): string | undefined {
  const value = (req as Record<string, unknown> | null | undefined)?._uploadTempPath;
  return typeof value === "string" ? value : undefined;
}

export async function deleteTempFile(filePath: string | undefined): Promise<void> {
  if (!filePath) return;
  try {
    await fs.unlink(filePath);
  } catch {
    // Best effort: missing files and races are fine.
  }
}

// ---- Concurrency limit --------------------------------------------------

let activeAnalyses = 0;

export function getActiveAnalyses(): number {
  return activeAnalyses;
}

export function getMaxConcurrentAnalyses(): number {
  return MAX_CONCURRENT_ANALYSES;
}

export function tryAcquireAnalysisSlot(): boolean {
  if (activeAnalyses >= MAX_CONCURRENT_ANALYSES) return false;
  activeAnalyses += 1;
  return true;
}

export function releaseAnalysisSlot(): void {
  activeAnalyses = Math.max(0, activeAnalyses - 1);
}

// ---- Orphan cleanup ------------------------------------------------------
// Temp files are deleted in a `finally` after every analysis, on multer
// errors, and when the client disconnects. Whatever survives (crash, kill,
// mid-upload abort) is reaped here: files older than ORPHAN_MAX_AGE_MS, plus
// files whose creator pid is demonstrably dead.

function isOwnTempFile(name: string): boolean {
  return name.startsWith(FILENAME_PREFIX) && name.endsWith(".zip");
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means a live process we may not signal; anything else is dead.
    return (err as NodeJS.ErrnoException)?.code === "EPERM";
  }
}

export async function sweepOrphanUploads(
  now = Date.now(),
  maxAgeMs = ORPHAN_MAX_AGE_MS
): Promise<{ deleted: number }> {
  let entries: string[];
  try {
    entries = await fs.readdir(UPLOAD_DIR);
  } catch {
    return { deleted: 0 };
  }
  let deleted = 0;
  for (const name of entries) {
    if (!isOwnTempFile(name)) continue;
    const full = path.join(UPLOAD_DIR, name);
    let mtimeMs: number;
    try {
      mtimeMs = (await fs.stat(full)).mtimeMs;
    } catch {
      continue;
    }
    let orphan = now - mtimeMs > maxAgeMs;
    if (!orphan) {
      const pidPart = name.slice(FILENAME_PREFIX.length).split("-")[0] ?? "";
      const pid = Number.parseInt(pidPart, 10);
      if (Number.isFinite(pid) && pid > 0 && pid !== process.pid && !pidAlive(pid)) {
        orphan = true;
      }
    }
    if (orphan) {
      try {
        await fs.unlink(full);
        deleted += 1;
      } catch {
        // Races are fine.
      }
    }
  }
  return { deleted };
}

let sweepStarted = false;

export function startOrphanSweep(): void {
  if (sweepStarted) return;
  sweepStarted = true;
  void sweepOrphanUploads().catch(() => {});
  const timer = setInterval(() => {
    void sweepOrphanUploads().catch(() => {});
  }, ORPHAN_SWEEP_INTERVAL_MS);
  if (typeof timer.unref === "function") timer.unref();
}
