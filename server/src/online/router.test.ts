import test from "node:test";
import assert from "node:assert/strict";
import type { Router } from "express";
import { createApp } from "../app.js";
import { createOnlineRouter, getActiveOnlineAnalyses } from "./router.js";

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

test("online router exposes POST /analyze", () => {
  const routes = collectRouterRoutes(createOnlineRouter());
  assert.ok(routes.has("POST /analyze"), "missing POST /analyze");
});

test("online router is mounted under /api/online", () => {
  const app = createApp();
  const stack = (
    app as unknown as { _router?: { stack?: Array<{ regexp?: RegExp }> } }
  )._router?.stack;
  const mounted = (stack ?? []).some((layer) => layer.regexp?.source.includes("online"));
  assert.ok(mounted, "online router not mounted");
});

test("online concurrency counter starts at zero", () => {
  assert.equal(getActiveOnlineAnalyses(), 0);
});
