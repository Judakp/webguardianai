import { Router, type Request, type Response, type NextFunction } from "express";
import { MulterError } from "multer";
import { promises as fs } from "node:fs";
import {
  IntakeError,
  MAX_ARCHIVE_BYTES,
  toPublicInventory,
  type PublicInventory,
} from "./intake.js";
import { ANALYSIS_TIMEOUT_MS } from "./limits.js";
import { runExtractionInWorker, WorkerTimeoutError } from "./workerClient.js";
import {
  deleteTempFile,
  getRequestTempPath,
  multerUpload,
  releaseAnalysisSlot,
  startOrphanSweep,
  tryAcquireAnalysisSlot,
  UPLOAD_FIELD,
} from "./uploads.js";

export { toPublicInventory, type PublicInventory };

interface DiskUploadedFile {
  path: string;
  size: number;
  originalname: string;
}

function getUploadedFile(req: Request): DiskUploadedFile | undefined {
  return (req as Request & { file?: DiskUploadedFile }).file;
}

export function multerErrorHandler(
  err: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (err instanceof MulterError) {
    void deleteTempFile(getRequestTempPath(req));
    if (err.code === "LIMIT_FILE_SIZE") {
      res.status(413).json({ ok: false, error: "archive too large" });
      return;
    }
    res.status(400).json({ ok: false, error: "upload rejected" });
    return;
  }
  next(err);
}

export function createOfflineRouter(): Router {
  startOrphanSweep();
  const router = Router();

  router.post(
    "/analyze",
    (req, res, next) => {
      // If the client disconnects mid-upload, multer never reaches the
      // handler; this listener reaps the partial temp file. It must watch
      // the response, not the request: req "close" fires once the body is
      // fully read (before slow analyses finish), while res "close" fires
      // after the response completes or on a genuine disconnect.
      res.on("close", () => {
        if (!res.writableEnded) void deleteTempFile(getRequestTempPath(req));
      });
      next();
    },
    multerUpload.single(UPLOAD_FIELD),
    async (req: Request, res: Response) => {
      const file = getUploadedFile(req);
      if (!file) {
        res.status(400).json({ ok: false, error: "missing file field 'project'" });
        return;
      }
      const tempPath = file.path;
      if (!tryAcquireAnalysisSlot()) {
        await deleteTempFile(tempPath);
        res.status(429).json({ ok: false, error: "server busy, try again later", code: "busy" });
        return;
      }
      const aborter = new AbortController();
      let finished = false;
      const onClose = (): void => {
        if (!finished) aborter.abort();
      };
      res.on("close", onClose);
      try {
        let size = file.size;
        try {
          size = (await fs.stat(tempPath)).size;
        } catch {
          throw new IntakeError("not-a-zip", "upload was removed before analysis");
        }
        if (size > MAX_ARCHIVE_BYTES) {
          throw new IntakeError(
            "too-large",
            `archive is ${size} bytes, limit is ${MAX_ARCHIVE_BYTES}`
          );
        }
        const outcome = await runExtractionInWorker(tempPath, {
          timeoutMs: ANALYSIS_TIMEOUT_MS,
          signal: aborter.signal,
        });
        if (!outcome.ok) {
          res.status(outcome.status).json({ ok: false, error: outcome.message, code: outcome.code });
          return;
        }
        res.json({ ok: true, inventory: outcome.inventory });
      } catch (err) {
        if (aborter.signal.aborted) return;
        if (err instanceof WorkerTimeoutError) {
          if (!res.writableEnded) {
            res.status(504).json({ ok: false, error: "analysis timed out", code: "timeout" });
          }
          return;
        }
        if (err instanceof IntakeError) {
          if (!res.writableEnded) {
            res.status(err.status).json({ ok: false, error: err.message, code: err.code });
          }
          return;
        }
        if (!res.writableEnded) {
          res.status(400).json({ ok: false, error: "could not read archive" });
        }
      } finally {
        finished = true;
        res.removeListener("close", onClose);
        releaseAnalysisSlot();
        await deleteTempFile(tempPath);
      }
    }
  );

  router.use(multerErrorHandler);
  return router;
}
