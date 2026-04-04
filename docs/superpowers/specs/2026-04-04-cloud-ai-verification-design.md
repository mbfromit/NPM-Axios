# Cloud AI Verification for RatCatcher

**Date:** 2026-04-04
**Status:** Approved

## Context

RatCatcher's `feature/ai-verification` branch runs AI finding verification locally via Ollama during the scan. This limits adoption since users need a GPU. We're moving AI to an AWS EC2 GPU instance (g6e.xlarge, L40S 45GB VRAM, Ollama with gemma4:31b) accessed through a Cloudflare Tunnel.

**Key design decision:** AI verification is an **on-demand admin action** via an "Evaluate with AI" button on the dashboard — not automatic during scan/submission. Admins control when AI is used.

## Architecture

```
User's Machine                Cloudflare                         AWS EC2 (g6e.xlarge)
+----------------+   HTTPS   +-------------------+   Tunnel     +------------------+
|  PowerShell    |---------->|  Worker           |------------>|  cloudflared      |
|  Scanner       |           |  (submit.js)      |             |       |           |
|                |           |                   |             |  Caddy (:8080)    |
|  Submits raw   |           |  Admin clicks     |             |  API key check    |
|  scan results  |           |  "Evaluate with   |             |       |           |
|  (no AI)       |           |   AI" button      |             |  Ollama (:11434)  |
+----------------+           |                   |             |  gemma4:31b       |
                             +-------------------+             +------------------+
```

### Data Flow

1. Scanner runs 10 checks on user's machine, collects findings
2. Scanner POSTs scan metadata + HTML reports to Cloudflare Worker (`/submit`)
3. Worker stores the submission in D1 and reports in R2 (existing behavior, no AI)
4. Admin reviews submissions on dashboard
5. Admin clicks "Evaluate with AI" button on a submission row
6. Worker extracts findings from the stored Technical Report HTML
7. Worker sends each finding to Ollama via Cloudflare Tunnel for verification
8. Worker stores per-finding verdicts in `finding_ai_verdicts` table
9. Worker computes aggregate `ai_verdict` and updates submission record
10. Dashboard updates to show AI verdict badges

### Security Model

**Cloudflare Tunnel (Zero Trust)**
- `cloudflared` runs on EC2, establishes outbound-only tunnel to Cloudflare
- **Zero inbound ports open** on EC2 — no public attack surface
- Traffic encrypted end-to-end through Cloudflare's network

**EC2 Security Group**
- All inbound traffic blocked (SSH only via SSM if needed)
- Ollama listens on `localhost:11434` only — not bound to any public interface

**API Key (Defense in Depth)**
- Cloudflare Worker holds an API key as a Worker Secret
- Sent as `X-API-Key` header on every request through the tunnel
- Caddy sidecar on EC2 validates the key before proxying to Ollama
- This prevents abuse even if the tunnel were somehow compromised

## Components

### 1. EC2 Setup (AWS)

**Instance:** g6e.xlarge (L40S GPU, 45GB VRAM, 4 vCPUs, 32GB RAM)
**Software:**
- Ollama (already installed) with `gemma4:31b` model pulled
- `cloudflared` — Cloudflare Tunnel daemon
- Caddy — lightweight reverse proxy for API key validation

**Caddy config:**
- Listens on `localhost:8080`
- Validates `X-API-Key` header against a configured secret
- Proxies valid requests to `localhost:11434` (Ollama)
- Returns 401 for missing/invalid keys

**cloudflared config:**
- Tunnel exposes `localhost:8080` (Caddy, not Ollama directly)
- Runs as a systemd service for auto-restart

### 2. Cloudflare Worker — New AI Endpoints

**New file: `cloudflare/src/handlers/ai-verify.js`**

Ports the system prompt, reference article, and verdict parsing from `Invoke-FindingVerification.ps1` to JavaScript:
- `verifySubmissionFindings(submissionId, env)` — fetches Technical Report HTML from R2, extracts findings, sends each to Ollama, stores per-finding verdicts, computes aggregate verdict
- Model: `gemma4:31b`, temperature 0.1, stream false
- Verdict format: `VERDICT: <Confirmed|Likely|Unlikely|FalsePositive> | REASON: <text>`

**New API endpoints:**
- `POST /api/submissions/:id/ai-verify` — admin-triggered single submission evaluation
- `GET /api/submissions/:id/ai-verdicts` — returns per-finding AI verdicts for report view
- `POST /api/ai-verify-all` — bulk evaluate all unreviewed submissions (uses `ctx.waitUntil()`)

**Worker Secrets (via `wrangler secret put`):**
- `AI_TUNNEL_URL` — The Cloudflare Tunnel hostname
- `AI_API_KEY` — API key for Caddy validation on EC2

**Aggregate logic:**
- Any finding `Confirmed` or `Likely` → `AI_COMPROMISE`
- All findings `FalsePositive` or `Unlikely` → `AI_FALSE_POSITIVE`
- No findings → `AI_CLEAN`

**Error handling:** Fail-open. If Ollama unreachable, return error to admin (not silently fail).

### 3. Dashboard UI Changes

**Per-row "Evaluate with AI" button:**
- Each submission row gets an "AI Eval" button in the Actions column
- If already evaluated: shows "AI Reviewed" (green, disabled) instead
- Clicking shows spinner/pulsing state, calls `POST /api/submissions/:id/ai-verify`
- On completion: button changes to "AI Reviewed", row updates with verdict badges

**Bulk "Evaluate All" button:**
- In pager/toolbar area (admin-only, like Delete and CSV Export)
- Calls `POST /api/ai-verify-all`, shows count of queued items

**Report view integration:**
- When admin opens Technical Report for an AI-evaluated submission
- Per-finding AI verdict badges injected into HTML (reuses ack.js pattern)
- `[AI: Confirmed Threat]` (red) or `[AI: False Positive]` (green) with reasoning

### 4. PowerShell Scanner Changes

**Remove local AI verification:**
- Remove `-OllamaUrl` and `-OllamaModel` parameters from `Invoke-RatCatcher.ps1`
- Remove `Invoke-FindingVerification.ps1` (no longer needed client-side)
- Remove the "AI Verification" section from the scanner flow
- Remove `ai_verdict` from `Submit-ScanToApi.ps1`
- Scanner submits raw results; AI runs server-side on admin demand

### 5. D1 Schema Changes

**New table: `finding_ai_verdicts`**
```sql
CREATE TABLE IF NOT EXISTS finding_ai_verdicts (
    id TEXT PRIMARY KEY,
    submission_id TEXT NOT NULL,
    finding_index INTEGER NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    verdict TEXT NOT NULL,
    reason TEXT,
    verified_at TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
);
CREATE INDEX idx_faiv_submission ON finding_ai_verdicts(submission_id);
```

Existing `ai_verdict` column on `submissions` table remains — stores aggregate verdict.

## Model Details

| Property | Value |
|----------|-------|
| Model | gemma4:31b (Dense) |
| Parameters | 31B (all active) |
| VRAM Required | ~20-24GB (Q4 quantization) |
| Available VRAM | 45GB (L40S) |
| Arena Ranking | #3 open model |
| Instance | g6e.xlarge (~$1.86/hr) |
| Inference | ~5-15s per finding (estimated) |

## Verification Plan

1. **EC2 health:** `curl localhost:11434/api/tags` returns gemma4:31b in model list
2. **Tunnel connectivity:** `curl -H "X-API-Key: <key>" https://<tunnel-hostname>/api/tags` returns model list; without key returns 401
3. **AI eval button:** Submit a scan, click "AI Eval" on dashboard, verify spinner then AI verdict appears
4. **Report view:** Open Technical Report after AI eval, verify per-finding badges
5. **Bulk eval:** Test "Evaluate All" with multiple unreviewed submissions
6. **Fail-open test:** Stop Ollama on EC2, click "AI Eval" → verify error message, no crash
7. **Security test:** Attempt direct curl to EC2 IP:11434 → unreachable
