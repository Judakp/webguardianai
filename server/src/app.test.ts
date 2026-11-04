import test from "node:test";
import assert from "node:assert/strict";
import type { Express, Request, Response } from "express";
import { createApp, healthHandler, versionHandler } from "./app.js";

function mockRes() {
  return {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
}

function collectRoutes(app: Express): Set<string> {
  const found = new Set<string>();
  const router = (
    app as unknown as {
      _router?: {
        stack?: Array<{ route?: { path?: unknown; methods?: Record<string, boolean> } }>;
      };
    }
  )._router;
  for (const layer of router?.stack ?? []) {
    const route = layer.route;
    if (!route || typeof route.path !== "string") continue;
    for (const [method, enabled] of Object.entries(route.methods ?? {})) {
      if (enabled) found.add(`${method.toUpperCase()} ${route.path}`);
    }
  }
  return found;
}

test("healthHandler returns ok", () => {
  const res = mockRes();
  healthHandler({} as Request, res as unknown as Response);
  assert.deepEqual(res.body, { status: "ok" });
});

test("versionHandler returns MVP version", () => {
  const res = mockRes();
  versionHandler({} as Request, res as unknown as Response);
  assert.deepEqual(res.body, { version: "0.1.0", phase: "online-mvp" });
});

test("routes are wired on the app", () => {
  const routes = collectRoutes(createApp());
  assert.ok(routes.has("GET /api/health"), "missing GET /api/health");
  assert.ok(routes.has("GET /api/version"), "missing GET /api/version");
});
