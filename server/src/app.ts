import express, { type Express, type Request, type Response } from "express";
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
  app.use(express.json({ limit: "1mb", strict: false }));

  app.get("/api/health", healthHandler);
  app.get("/api/version", versionHandler);
  app.use("/api/offline", createOfflineRouter());
  app.use("/api/online", createOnlineRouter());

  return app;
}
