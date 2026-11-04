// Central intake limits for the offline ZIP pipeline.
//
// Policy: reject any file that individually exceeds MAX_FILE_BYTES.
// Rationale: fail-closed and simple to enforce mid-stream (abort on first
// over-limit chunk). Archives that trip this should move the file out of the
// project or into an excluded generated directory and re-upload. The
// `too-large` skipped reason is retained in the type for compatibility but is
// no longer emitted.

function readEnvInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

export const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
export const MAX_EXTRACTED_BYTES = 300 * 1024 * 1024;
export const MAX_FILES = 5000;
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_PATH_CHARS = 256;
export const BINARY_PROBE_BYTES = 8192;

// Streaming slice size fed to the ZIP parser. Small enough to enforce limits
// promptly, large enough to keep throughput high.
export const INTAKE_CHUNK_BYTES = 64 * 1024;

// Maximum concurrent /analyze extractions per server process. Extra requests
// get an immediate 429 so memory, CPU, and temp-disk usage stay bounded.
export const MAX_CONCURRENT_ANALYSES = readEnvInt("WEBGUARDIAN_MAX_CONCURRENT", 2);

// Wall-clock budget for one worker extraction (ms). Exceeding it terminates
// the worker, deletes the temp upload, and returns 504.
export const ANALYSIS_TIMEOUT_MS = readEnvInt("WEBGUARDIAN_ANALYSIS_TIMEOUT_MS", 120_000);

// Temp uploads older than this are orphans (a normal upload finishes within
// the analysis timeout) and are deleted by the periodic sweep.
export const ORPHAN_MAX_AGE_MS = readEnvInt("WEBGUARDIAN_ORPHAN_MAX_AGE_MS", 3_600_000);
export const ORPHAN_SWEEP_INTERVAL_MS = readEnvInt("WEBGUARDIAN_ORPHAN_SWEEP_MS", 600_000);
