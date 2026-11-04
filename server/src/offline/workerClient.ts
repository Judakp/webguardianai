import { Worker, type WorkerOptions } from "node:worker_threads";
import type { PublicInventory } from "./intake.js";

export type WorkerOutcome =
  | { ok: true; inventory: PublicInventory }
  | { ok: false; code: string; message: string; status: number };

export class WorkerTimeoutError extends Error {
  constructor(message = "analysis timed out") {
    super(message);
    this.name = "WorkerTimeoutError";
  }
}

export class WorkerAbortedError extends Error {
  constructor(message = "analysis aborted") {
    super(message);
    this.name = "WorkerAbortedError";
  }
}

export class WorkerCrashedError extends Error {
  constructor(message = "analysis worker failed") {
    super(message);
    this.name = "WorkerCrashedError";
  }
}

export interface WorkerRunOptions {
  timeoutMs: number;
  signal?: AbortSignal;
}

// Runs one extraction in an isolated worker thread. Always settles: worker
// success/failure messages resolve, while timeouts, cancellations, and
// crashes reject. The worker is terminated on every path.
export function runExtractionInWorker(
  filePath: string,
  opts: WorkerRunOptions
): Promise<WorkerOutcome> {
  return new Promise<WorkerOutcome>((resolve, reject) => {
    let settled = false;
    const workerOpts = { workerData: { filePath }, type: "module" } as WorkerOptions;
    let worker: Worker;
    try {
      worker = new Worker(new URL("./extract.worker.js", import.meta.url), workerOpts);
    } catch (err) {
      reject(err instanceof Error ? err : new WorkerCrashedError(String(err)));
      return;
    }

    const timer = setTimeout(() => {
      fail(new WorkerTimeoutError());
    }, opts.timeoutMs);
    if (typeof timer.unref === "function") timer.unref();

    function cleanup(): void {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      worker.removeAllListeners();
    }
    function fail(err: Error): void {
      if (settled) return;
      settled = true;
      cleanup();
      void worker.terminate().finally(() => reject(err));
    }
    function onAbort(): void {
      fail(new WorkerAbortedError());
    }

    if (opts.signal?.aborted) {
      fail(new WorkerAbortedError());
      return;
    }
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    worker.once("message", (message: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      const outcome = message as WorkerOutcome;
      void worker.terminate().finally(() => resolve(outcome));
    });
    worker.once("error", (err: Error) => {
      fail(new WorkerCrashedError(err.message));
    });
    worker.once("exit", (code: number) => {
      if (!settled) fail(new WorkerCrashedError(`analysis worker exited with code ${code}`));
    });
  });
}
