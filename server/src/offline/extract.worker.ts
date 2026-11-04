import { parentPort, workerData } from "node:worker_threads";
import { readFileSync, statSync } from "node:fs";
import {
  extractZipPublicFromBytes,
  IntakeError,
  MAX_ARCHIVE_BYTES,
  type PublicInventory,
} from "./intake.js";

interface WorkerInput {
  filePath: string;
}

type WorkerOutcome =
  | { ok: true; inventory: PublicInventory }
  | { ok: false; code: string; message: string; status: number };

function report(outcome: WorkerOutcome): void {
  parentPort?.postMessage(outcome);
}

// One-shot extraction worker: reads the size-capped temp upload and runs the
// same bounded streaming parser as the in-memory path, but discards file
// contents and returns only the public inventory. CPU and heap pressure stay
// off the Express event loop; a worker OOM kills only this job.
try {
  const { filePath } = (workerData ?? {}) as Partial<WorkerInput>;
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new IntakeError("not-a-zip", "missing upload path");
  }
  let size: number;
  try {
    size = statSync(filePath).size;
  } catch {
    throw new IntakeError("not-a-zip", "upload was removed before analysis");
  }
  if (size > MAX_ARCHIVE_BYTES) {
    throw new IntakeError(
      "too-large",
      `archive is ${size} bytes, limit is ${MAX_ARCHIVE_BYTES}`
    );
  }
  const data = readFileSync(filePath);
  report({ ok: true, inventory: extractZipPublicFromBytes(data) });
} catch (err) {
  if (err instanceof IntakeError) {
    report({ ok: false, code: err.code, message: err.message, status: err.status });
  } else {
    report({ ok: false, code: "not-a-zip", message: "could not read archive", status: 400 });
  }
}
