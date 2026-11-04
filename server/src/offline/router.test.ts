import test from "node:test";
import assert from "node:assert/strict";
import type { Request, Response, NextFunction, Router } from "express";
import { MulterError } from "multer";
import { createApp } from "../app.js";
import {
  createOfflineRouter,
  multerErrorHandler,
  toPublicInventory,
  type PublicInventory,
} from "./router.js";

function collectRouterRoutes(router: Router): Set<string> {
  const found = new Set<string>();
  const stack = (
    router as unknown as {
      stack?: Array<{ route?: { path?: unknown; methods?: Record<string, boolean> } }>;
    }
  ).stack;
  for (const layer of stack ?? []) {
    const route = layer.route;
    if (!route || typeof route.path !== "string") continue;
    for (const [method, enabled] of Object.entries(route.methods ?? {})) {
      if (enabled) found.add(`${method.toUpperCase()} ${route.path}`);
    }
  }
  return found;
}

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

test("offline router exposes POST /analyze", () => {
  const routes = collectRouterRoutes(createOfflineRouter());
  assert.ok(routes.has("POST /analyze"), "missing POST /analyze");
});

test("offline router is mounted under /api/offline", () => {
  const app = createApp();
  const stack = (
    app as unknown as { _router?: { stack?: Array<{ regexp?: RegExp }> } }
  )._router?.stack;
  const mounted = (stack ?? []).some((layer) => layer.regexp?.source.includes("offline"));
  assert.ok(mounted, "offline router not mounted");
});

test("multer size errors map to 413, other upload errors to 400", () => {
  const tooLarge = mockRes();
  multerErrorHandler(
    new MulterError("LIMIT_FILE_SIZE"),
    {} as Request,
    tooLarge as unknown as Response,
    (() => {}) as NextFunction
  );
  assert.equal(tooLarge.statusCode, 413);

  const rejected = mockRes();
  multerErrorHandler(
    new MulterError("LIMIT_UNEXPECTED_FILE"),
    {} as Request,
    rejected as unknown as Response,
    (() => {}) as NextFunction
  );
  assert.equal(rejected.statusCode, 400);

  let nextCalled = false;
  multerErrorHandler(new Error("boom"), {} as Request, mockRes() as unknown as Response, (() => {
    nextCalled = true;
  }) as NextFunction);
  assert.equal(nextCalled, true);
});

test("public inventory strips file contents", () => {
  const result: PublicInventory = toPublicInventory({
    files: [
      { path: "a.js", size: 3, language: "javascript", content: "sekret", manifest: false },
    ],
    skipped: [],
    archiveBytes: 10,
    extractedBytes: 3,
  });
  assert.deepEqual(result.files, [{ path: "a.js", size: 3, language: "javascript", manifest: false }]);
  assert.ok(!("content" in result.files[0]!));
});
