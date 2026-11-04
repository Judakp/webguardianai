import { Router, type Request, type Response } from "express";
import { OnlineError } from "./errors.js";
import { ONLINE_MAX_CONCURRENT_ANALYSES } from "./limits.js";
import { analyzeOnlineSite, type AnalyzeOnlineOptions } from "./pipeline.js";

let activeOnlineAnalyses = 0;

export function getActiveOnlineAnalyses(): number {
  return activeOnlineAnalyses;
}

// Optional deps exist so HTTP-level tests can inject a mocked resolver/fetch
// (no network). Production callers pass nothing and get live behavior.
export function createOnlineRouter(deps: AnalyzeOnlineOptions = {}): Router {
  const router = Router();

  router.post("/analyze", async (req: Request, res: Response) => {
    const url = (req.body as { url?: unknown } | undefined)?.url;
    if (typeof url !== "string" || url.trim() === "") {
      res.status(400).json({ ok: false, error: "missing URL field 'url'", code: "invalid-url" });
      return;
    }
    if (activeOnlineAnalyses >= ONLINE_MAX_CONCURRENT_ANALYSES) {
      res.status(429).json({ ok: false, error: "server busy, try again later", code: "busy" });
      return;
    }
    activeOnlineAnalyses += 1;
    try {
      const report = await analyzeOnlineSite(url, deps);
      res.json({ ok: true, report });
    } catch (err) {
      if (err instanceof OnlineError) {
        if (!res.writableEnded) {
          res.status(err.status).json({ ok: false, error: err.message, code: err.code });
        }
        return;
      }
      if (!res.writableEnded) {
        res.status(502).json({ ok: false, error: "analysis failed" });
      }
    } finally {
      activeOnlineAnalyses = Math.max(0, activeOnlineAnalyses - 1);
    }
  });

  return router;
}
