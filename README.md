# WebGuardian AI

**Inspect. Understand. Fix. Verify.**

An AI-powered web quality assurance agent that helps developers detect, understand, and investigate website issues through deterministic analysis, browser inspection, and Meta Muse Spark.

## Live Demo

- **Frontend:** https://webguardianai-1.onrender.com/
- **Backend API:** https://webguardian-2.onrender.com
- **Demo Video:** https://youtu.be/H6bRXb8AMYA

## The Problem

Website quality assurance often requires developers to combine several tools to identify security weaknesses, technical errors, SEO issues, and rendering problems.

Some issues are visible only after a page has been rendered in a browser, while others can be detected directly from HTTP responses and HTML content. Understanding these findings and deciding what to fix can also take time.

AI-powered analysis can help explain technical issues, but recommendations need reliable evidence to remain useful.

## Our Solution

WebGuardian AI brings these capabilities together in one analysis workflow.

It securely inspects a public website, collects technical evidence, runs deterministic quality checks, examines the rendered page using Playwright, and uses Meta Muse Spark 1.3 to provide additional evidence-grounded reasoning.

Rather than relying entirely on AI, WebGuardian AI combines deterministic checks with AI-assisted interpretation. This allows developers to investigate website issues while retaining access to the technical evidence behind the report.

## Current MVP

The **Online Site** is the primary hackathon demonstration.

The Offline Project backend remains in the repository, but its functionality is intentionally hidden from the web interface while the MVP focuses on online website analysis.

### Key Features

- **Secure website inspection:** Accepts public HTTP and HTTPS URLs with strict URL and destination validation.
- **Security analysis:** Checks HTTP security headers, cookies, forms, mixed content, and other common security signals.
- **SEO and quality checks:** Inspects page titles, headings, links, images, and other HTML quality indicators.
- **Deterministic analysis:** Uses predefined checks to identify technical issues without depending on an AI model.
- **Browser inspection:** Uses isolated Playwright Chromium sessions to identify runtime console errors, failed resources, empty rendered documents, and horizontal overflow.
- **AI-assisted reasoning:** Uses Meta Muse Spark 1.3 to provide additional explanations and recommendations based on collected evidence.
- **Resilient reporting:** If Muse Spark or browser inspection is unavailable, the deterministic report remains available and the application reports the limitation.

## How It Works

WebGuardian AI follows a multi-stage analysis process.

### 1. Secure URL Validation

The submitted URL is validated before any request is made.

The server checks DNS resolution and blocks private, loopback, link-local, metadata, CGNAT, multicast, reserved, and other non-public IPv4 and IPv6 destinations.

Every redirect is validated again. Connections use validated-IP pinning to prevent a second DNS lookup at connection time, while TLS continues to authenticate the original hostname.

### 2. Static HTML Inspection

The server fetches the public page and extracts technical evidence without executing its JavaScript.

The deterministic engine checks transport, security headers, cookies, forms, mixed content, SEO, headings, links, images, and other quality signals.

### 3. Browser Inspection with Playwright

Playwright launches an isolated headless Chromium session to inspect the rendered page.

This separate browser layer can detect issues that are not necessarily visible in static HTML, including:

- JavaScript console errors.
- Failed network resources.
- Empty rendered documents.
- Horizontal overflow.

Browser inspection is optional and best-effort. If Chromium cannot launch or the browser phase fails, the static HTML report remains available.

### 4. AI-Assisted Reasoning with Meta Muse Spark

When `MODEL_API_KEY` is configured, the backend sends structured technical evidence to Meta Muse Spark 1.3.

Muse Spark provides additional reasoning and recommendations based on the collected findings.

The AI layer does not replace the deterministic engine. Website content is treated as untrusted data, and the prompt explicitly prevents page content from becoming instructions.

AI findings are additional reasoning signals. Developers can still inspect the underlying deterministic evidence to verify recommendations.

## Why Meta Muse Spark?

Muse Spark adds an interpretation layer to the technical analysis.

The deterministic engine identifies issues through predefined checks, while Playwright contributes observations from the rendered page. Muse Spark then helps interpret the collected evidence and provide additional recommendations.

This combination is designed to make technical findings easier to understand without making the application entirely dependent on AI-generated answers.

The integration uses Meta's Model API with backend-only credentials and structured JSON output.

### Muse Spark Integration

The current implementation uses:

- **Base URL:** `https://api.meta.ai/v1`
- **Model:** `muse-spark-1.3`
- **Authentication:** Bearer authentication using `MODEL_API_KEY`
- **API:** OpenAI-compatible Chat Completions and Responses APIs
- **Structured output:** Chat Completions `response_format`

WebGuardian AI uses Node.js native `fetch` rather than introducing another SDK dependency.

The API key is read exclusively on the backend. It is never exposed to the React client.

If the key is missing or the AI request fails, WebGuardian AI continues with its deterministic analysis and clearly reports that AI reasoning is unavailable.

## Technical Architecture

```text
                 Browser / React UI
                         |
                         v
                POST /api/online/analyze
                         |
                         v
                Secure URL validation
                         |
                         v
             DNS validation + IP pinning
                         |
                         v
                  Static HTML fetch
                         |
                +--------+--------+
                |                 |
                v                 v
         Deterministic checks   Playwright
                                  Chromium
                |                 |
                |                 v
                |          Browser findings
                |                 |
                +--------+--------+
                         |
                         v
                Structured evidence
                         |
                         v
                   Muse Spark 1.3
                         |
                         v
                   Final report
```

### Technology Stack

- **Frontend:** React, TypeScript, Vite.
- **Backend:** Node.js, Express.
- **Browser automation:** Playwright and Chromium.
- **AI model:** Meta Muse Spark 1.3.
- **Communication:** HTTP API and structured JSON.
- **Networking:** Native Node.js fetch with validated-IP transport.
- **Deployment:** Render.

## Security and Network Safety

Security is an important part of WebGuardian AI's architecture.

The online analyzer implements several safeguards:

- Blocks private, loopback, link-local, metadata, CGNAT, multicast, reserved, and other non-public IP destinations.
- Revalidates every redirect hop.
- Pins connections to validated IP addresses.
- Preserves TLS hostname authentication.
- Caps response-body size.
- Applies DNS, connection, body-idle, and overall analysis timeouts.
- Prevents static HTML inspection from executing page scripts.
- Treats website content as untrusted input for AI reasoning.

### Playwright Network Isolation

Chromium's direct hostname resolution is disabled.

HTTP and HTTPS browser requests are intercepted and fetched by the Node.js server through the same DNS validation and pinned-IP transport used by the static analyzer.

Redirects are revalidated, non-GET/HEAD methods are blocked, and service workers and downloads are disabled.

This is defense in depth, not a replacement for production network restrictions. A network-restricted container or host egress policy is recommended as an additional production boundary.

## Playwright Browser Inspection

Playwright is a separate browser automation layer. It does not call Muse Spark.

Install the browser after installing project dependencies:

```bash
npm install
npx playwright install chromium
```

Enable browser inspection using the server environment variable:

```powershell
$env:PLAYWRIGHT_ENABLED="true"
```

To disable it temporarily:

```powershell
$env:PLAYWRIGHT_ENABLED="false"
```

### Render Deployment Configuration

The backend is deployed on Render.

**Backend URL:**

https://webguardian-2.onrender.com

The backend build command is:

```bash
npm ci && npx playwright install chromium && npm run build -w server
```

The following environment variable is required for the current Render browser installation configuration:

```text
PLAYWRIGHT_BROWSERS_PATH=0
```

This tells Playwright to use its project-local browser installation path, ensuring that Chromium can be located in the deployed environment.

Browser inspection is limited to the initial page at a desktop viewport. It does not submit forms, click arbitrary controls, log in, or crawl multiple pages.

## Getting Started Locally

### Requirements

- Node.js and npm.
- Git.
- A Meta Model API key for Muse Spark reasoning (optional).
- Chromium installed through Playwright for browser inspection (optional).

### 1. Clone the Repository

```bash
git clone https://github.com/Judakp/webguardianai.git
cd webguardianai
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Set the variables in the PowerShell terminal used to start the API:

```powershell
$env:PLAYWRIGHT_ENABLED="true"
$env:PLAYWRIGHT_BROWSERS_PATH="0"
$env:MODEL_API_KEY="your_meta_model_api_key"
$env:META_MODEL="muse-spark-1.3"
```

The server does not automatically load `.env` files.

If you do not have a Meta API key, omit `MODEL_API_KEY`. Static analysis and browser inspection can still work.

**Never put a real API key in the React client, source code, README, Git repository, screenshots, or shared ZIP files.**

### 4. Install Chromium

```bash
npx playwright install chromium
```

### 5. Start the API Server

Open a PowerShell terminal:

```bash
npm run dev:server
```

The API listens on:

```text
http://localhost:3001
```

### 6. Start the Frontend

Open a second terminal:

```bash
npm run dev:client
```

The Vite interface listens on:

```text
http://localhost:5173
```

The frontend proxies `/api` requests to the backend.

### 7. Check the API

Health check:

```powershell
Invoke-RestMethod http://localhost:3001/api/health
```

Version:

```powershell
Invoke-RestMethod http://localhost:3001/api/version
```

## Verification and Tests

Run the project's verification commands from the repository root:

```bash
npm run typecheck
npm run build
npm run test
```

The full test suite includes offline security tests and can take longer than online unit tests because it deliberately exercises archive limits and decompression-bomb protections.

## Current Limitations

WebGuardian AI is an MVP, and its current scope is intentionally limited.

- One page is analyzed per request, with up to five redirects.
- There is no site-wide crawler or sitemap crawl.
- Browser rendering is limited to the initial page at a desktop viewport.
- No login, arbitrary form submission, or automated interaction with page controls is performed.
- Broken-link verification is not enabled by default because the MVP avoids additional outbound requests beyond the inspected page.
- The AI layer reasons over extracted evidence rather than the complete raw HTML source.
- AI findings are additional reasoning signals and should be verified against the deterministic evidence.
- The Offline Project remains backend-only and is not part of the primary hackathon demonstration.

## Repository Hygiene

Do not commit or submit:

- `node_modules/`
- `.npm-cache/`
- `.env`
- API keys or other credentials.
- Temporary test archives such as `big.zip` and `big.bin`.
- Generated temporary directories.

The source ZIP for a final submission should contain the application source and lockfile, not local dependency caches.

## Project

**WebGuardian AI — Inspect. Understand. Fix. Verify.**

Built for the Meta Global AI Developer Hackathon 2026.

- **Repository:** https://github.com/Judakp/webguardianai
- **Backend API:** https://webguardian-2.onrender.com
- **Frontend:** Add the final Render Static Site URL.
- **Demo Video:** Add the published video URL.