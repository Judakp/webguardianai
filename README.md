# WebGuardian AI

**Inspect. Understand. Fix. Verify.**

WebGuardian AI is an online web quality-assurance agent. It securely fetches a public website, extracts HTML/HTTP evidence, runs deterministic checks, optionally inspects the rendered page in an isolated Playwright Chromium session, and — when `MODEL_API_KEY` is configured — asks Meta's Muse Spark for additional evidence-grounded reasoning.

## Current MVP

- **Online Site is the primary demo.** The Offline Project backend remains in the repository but is intentionally hidden from the web UI while the hackathon MVP is focused on online analysis.
- Secure `http://` / `https://` URL validation.
- SSRF protection for private, loopback, link-local, metadata, CGNAT, multicast, reserved and other non-public IPv4/IPv6 destinations.
- Every redirect hop is revalidated.
- Connections use validated-IP pinning so the production fetcher does not perform a second DNS lookup at connect time.
- TLS still authenticates the original hostname.
- Static HTML inspection never executes page scripts; the optional Playwright phase runs the public page in an isolated headless Chromium browser.
- 2 MiB response-body cap, 15 s body-idle timeout, 10 s per-hop fetch timeout, 10 s DNS timeout and 120 s overall analysis budget.
- Deterministic checks for transport, security headers, cookies, forms, mixed content, SEO, headings, links, images and common quality signals.
- **Playwright + Chromium** browser inspection for runtime console errors, failed resources, empty rendered documents, and horizontal overflow.
- Optional **Muse Spark 1.3** reasoning through Meta Model API, using backend-only `MODEL_API_KEY` credentials and structured JSON output.
- Website content is treated as untrusted data; the AI prompt explicitly prevents page text from becoming instructions.
- AI failure does not destroy the deterministic report: the UI falls back honestly and reports why AI was unavailable.


## Playwright browser inspection

Playwright is a separate browser automation layer; it does not call Muse Spark. It executes the public page in headless Chromium, collects bounded technical observations, and passes those structured findings to the existing deterministic/Muse Spark report pipeline.

Install the browser after installing project dependencies:

```powershell
npm install
npx playwright install chromium
```

Set `PLAYWRIGHT_ENABLED=true` in the server environment to enable browser inspection. Set it to `false` to use the HTML-only analyzer. Browser inspection is best-effort: if Chromium is unavailable or the browser phase fails, the HTML report is still returned.

**Network safety:** Chromium's direct hostname resolution is disabled. Every HTTP(S) browser request is intercepted and fetched by the Node server through the same DNS validation and pinned-IP transport used by the static analyzer. Redirects are revalidated, non-GET/HEAD methods are blocked, service workers and downloads are disabled, and request/response sizes are capped. This is defense in depth, not a substitute for running the server in a restricted container or egress-controlled environment in production.

The browser phase is intentionally limited in this MVP: it does not submit forms, click arbitrary controls, log in, or crawl multiple pages. It tests the initial page at a desktop viewport. Each HTTP(S) request is fetched by the server through DNS validation and pinned-IP transport; Chromium's direct DNS is disabled. Use a network-restricted container or host egress policy as an additional production boundary. Browser inspection is optional and best-effort; if Chromium cannot launch, the static HTML report remains available.

## Muse Spark integration

The current official Meta Model API documentation specifies:

- Base URL: `https://api.meta.ai/v1`
- Model: `muse-spark-1.3`
- Bearer authentication using `MODEL_API_KEY`
- OpenAI-compatible Chat Completions and Responses APIs
- Structured output through `response_format` for Chat Completions

WebGuardian uses the native Node.js `fetch` API rather than adding another SDK dependency. The key is read only on the backend. The `.env.example` file contains only a placeholder; copy the values into your PowerShell session or create a local `.env` for your own workflow (the server does not load `.env` automatically). Never include a real key in a shared ZIP.

**Muse Spark diagnostics:** the server logs request size, model, HTTP status and elapsed time, but never logs the API key or the submitted evidence. The Muse Spark request timeout is 60 seconds. If a request times out, compare the last `[WebGuardian][Muse Spark]` log entry to determine whether the server received an HTTP response.

Set the environment variables in the PowerShell terminal used to start the API (the server does not automatically load `.env` files):

```powershell
$env:PLAYWRIGHT_ENABLED="true"
$env:MODEL_API_KEY="your_meta_model_api_key"
$env:META_MODEL="muse-spark-1.3"
```

If you do not have a Meta API key yet, omit `MODEL_API_KEY`; the static and browser checks still work. To disable Chromium inspection temporarily, set `$env:PLAYWRIGHT_ENABLED="false"`.

Do **not** put the key in the React client, source code, README, ZIP, Git repository, or screenshots.

If `MODEL_API_KEY` is missing, WebGuardian still runs its HTML and (when enabled) Playwright checks and clearly reports `aiAvailable: false`.

## Architecture

```text
Browser / React UI
        |
        v
POST /api/online/analyze
        |
        v
Secure public URL validation
        |
        v
DNS validation + IP pinning + redirect validation
        |
        v
HTML fetch (static, no JS execution)
        |
        +----------------------+
        |                      |
        v                      v
Deterministic checks    Playwright / Chromium
        |                      |
        |                      v
        |               Browser findings
        |                      |
        +----------+-----------+
                   |
                   v
          Structured evidence
                   |
                   v
             Muse Spark 1.3
                   |
                   +
                   v
              Final report
```

## Launch locally

Install dependencies once on your Windows machine:

```powershell
npm install
```

API terminal:

```powershell
npm run dev:server
```

The API listens on `http://localhost:3001`.

UI terminal:

```powershell
npm run dev:client
```

The Vite UI listens on `http://localhost:5173` and proxies `/api` to the backend.

Health check:

```powershell
Invoke-RestMethod http://localhost:3001/api/health
```

Version:

```powershell
Invoke-RestMethod http://localhost:3001/api/version
```

## Verification

```powershell
npm run typecheck
npm run build
npm run test
```

The full test suite includes the offline security tests and can take longer than the online unit tests because it deliberately exercises archive limits and decompression-bomb protections.

## Important limitations

- One page per analysis plus up to five redirects. There is no site-wide crawler or sitemap crawl.
- Browser rendering is limited to the initial page at a desktop viewport; no multi-page crawl, login, or arbitrary form submission is performed.
- Broken-link verification is not enabled by default because the MVP avoids extra outbound requests beyond the inspected page.
- The AI layer reasons only over extracted evidence, not the complete raw HTML source.
- AI findings are additional reasoning signals; the deterministic evidence remains visible and should be used to verify recommendations.
- Offline Project remains backend-only for now and is not part of the primary hackathon demo.

## Repository hygiene

Do not commit or submit:

- `node_modules/`
- `.npm-cache/`
- `.env`
- API keys or other credentials
- temporary test archives such as `big.zip` / `big.bin`
- generated temporary directories

The source ZIP for a final submission should contain the application source and lockfile, not local dependency caches.
