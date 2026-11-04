
import express, {
  type Express,
  type Request,
  type Response,
  type NextFunction,
} from "express";

import { createOfflineRouter } from "./offline/router.js";
import { createOnlineRouter } from "./online/router.js";

export function healthHandler(_req: Request, res: Response): void {
  res.json({ status: "ok" });
}

export function versionHandler(_req: Request, res: Response): void {
  res.json({ version: "0.1.0", phase: "online-mvp" });
}

export function createApp(): Express {
  const app = express();

  const clientOrigin = process.env.CLIENT_ORIGIN?.replace(/\/$/, "");

  // CORS: allow requests only from the configured frontend origin.
  app.use((req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;

    if (origin && clientOrigin && origin === clientOrigin) {
      res.setHeader("Access-Control-Allow-Origin", clientOrigin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    }

    if (req.method === "OPTIONS") {
      if (origin && origin !== clientOrigin) {
        res.sendStatus(403);
        return;
      }

      res.sendStatus(204);
      return;
    }

    next();
  });

  app.use(express.json({ limit: "1mb", strict: false }));

  app.get("/api/health", healthHandler);
  app.get("/api/version", versionHandler);

  app.use("/api/offline", createOfflineRouter());
  app.use("/api/online", createOnlineRouter());

  return app;
}
