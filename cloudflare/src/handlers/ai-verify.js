import { json, checkAdminPassword } from '../util.js'

const SYSTEM_PROMPT = `You are a cybersecurity analyst verifying forensic scanner findings against a known attack profile. You will receive:
1. A reference article describing the Axios NPM supply chain attack of March 31, 2026
2. A specific finding from a forensic scanner

Your job is to determine whether the finding is genuinely related to this specific attack or is likely a false positive (normal system activity unrelated to the attack).

RESPOND WITH EXACTLY ONE LINE in this format:
VERDICT: <Confirmed|Likely|Unlikely|FalsePositive> | REASON: <one sentence explanation>

Definitions:
- Confirmed: Finding directly matches a known IOC from the attack (exact package version, exact C2 domain/IP, exact file path, exact hash)
- Likely: Finding is consistent with the attack pattern but not an exact IOC match (e.g., suspicious file in temp created during attack window, persistence mechanism matching described techniques)
- Unlikely: Finding has weak or coincidental connection to the attack (e.g., port 8000 used by a known legitimate service, scheduled task from a trusted vendor)
- FalsePositive: Finding is clearly unrelated normal system activity (e.g., legitimate software update, well-known application persistence entry)

Be strict: only mark Confirmed for exact IOC matches. Lean toward FalsePositive for anything that looks like normal system operation.
Do not think out loud. Do not include any text before or after the verdict line.`

const ARTICLE_CONTEXT = `REFERENCE: Axios NPM Supply Chain Attack — March 31, 2026

The popular HTTP client Axios suffered a supply chain compromise after two malicious npm package versions (1.14.1 and 0.30.4) introduced a fake dependency called "plain-crypto-js" version 4.2.1. This dependency delivered a cross-platform remote access trojan (RAT) targeting Windows, macOS, and Linux systems.

ATTACK MECHANISM:
Its sole purpose is to execute a postinstall script that acts as a cross-platform RAT dropper, targeting macOS, Windows, and Linux. The malware contacts a command and control server and delivers platform-specific second-stage payloads before self-destructing and replacing its package.json with a clean version to evade forensic detection.

COMPROMISE DETAILS:
The attackers compromised the npm account credentials of primary Axios maintainer "jasonsaayman," bypassing GitHub Actions CI/CD pipelines. They changed the account's registered email to "ifstap@proton.me" and obtained a long-lived classic npm access token for direct registry access. The "plain-crypto-js" package was published by npm user "nrwise" with email "nrwise@proton.me."

TIMELINE:
- March 30, 2026, 05:57 UTC: Clean "plain-crypto-js@4.2.0" published
- March 30, 2026, 23:59 UTC: Malicious "plain-crypto-js@4.2.1" published
- March 31, 2026, 00:21 UTC: Axios "1.14.1" published with injected dependency
- March 31, 2026, 01:00 UTC: Axios "0.30.4" published with injected dependency

This was not opportunistic. The malicious dependency was staged 18 hours in advance. Three separate payloads were pre-built for three operating systems.

MALWARE CAPABILITIES BY PLATFORM:
macOS: Executes AppleScript payload fetching trojan from "sfrclak.com:8000," saves as "/Library/Caches/com.apple.act.mond," makes executable, launches via /bin/zsh, then deletes AppleScript.
Windows: Locates PowerShell binary, copies to "%PROGRAMDATA%\\wt.exe," writes VBScript to temp directory, fetches PowerShell RAT from C2 server, executes it, then deletes downloaded file.
Linux: Runs shell command via Node.js execSync to fetch Python RAT from server, saves to "/tmp/ld.py," executes in background using nohup.

C2 COMMUNICATION:
Each platform sends a distinct POST body to the same C2 URL — packages.npm.org/product0 (macOS), packages.npm.org/product1 (Windows), packages.npm.org/product2 (Linux). This allows the C2 to serve platform-appropriate payloads from a single endpoint.

RAT CAPABILITIES (all platforms):
- System fingerprinting
- 60-second beacon intervals
- Arbitrary payload execution
- Shell command execution
- File system enumeration
- Process enumeration
- Graceful self-termination

The Windows variant additionally creates "%PROGRAMDATA%\\system.bat" with download cradles and Registry Run keys for persistence across reboots.

FORENSIC EVASION:
The Node.js dropper removes the postinstall script, deletes the malicious package.json, and renames "package.md" (a clean manifest) to "package.json" to avoid detection during post-infection inspection.

ATTRIBUTION:
Elastic Security Labs noted potential overlap with WAVESHAPER, a C++ backdoor attributed to North Korean threat actor UNC1069, though attribution remains unconfirmed.

ADDITIONAL COMPROMISED PACKAGES:
Socket identified two packages distributing the same malware:
- @shadanai/openclaw (versions 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2)
- @qqbrowser/openclaw-qbot (version 0.0.130)

KNOWN INDICATORS OF COMPROMISE (IOCs):
- Packages: axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1
- C2 Domain: sfrclak.com
- C2 IP: 142.11.206.73
- C2 Port: 8000
- XOR Key: OrDeR_7077 (constant 333)
- File artifacts: /Library/Caches/com.apple.act.mond (macOS), %PROGRAMDATA%\\wt.exe (Windows), /tmp/ld.py (Linux)
- Persistence: Registry Run keys pointing to %PROGRAMDATA%, scheduled tasks with suspicious executors
- Known malicious hash (setup.js): e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09

REMEDIATION:
- Downgrade to Axios 1.14.0 or 0.30.3
- Rotate secrets and credentials immediately
- Remove "plain-crypto-js" from node_modules
- Assume full compromise if artifacts found
- Block egress to sfrclak.com
- Audit CI/CD pipeline runs using affected versions`

/**
 * Parse findings from a Technical Report HTML.
 * Each finding is a <div class="finding"> block containing .f-type and .f-row elements.
 */
function extractFindings(html) {
  const findings = []
  // Match each finding div — they start with <div class="finding and end at the next finding or section
  const findingRegex = /<div class="finding[" ][^>]*>([\s\S]*?)(?=<div class="finding[" ]|<div class="section|<\/body|$)/gi
  let match
  while ((match = findingRegex.exec(html)) !== null) {
    const block = match[0]

    // Extract finding type
    const typeMatch = block.match(/<span class="f-type">([\s\S]*?)<\/span>/i)
    const type = typeMatch ? stripTags(typeMatch[1]).trim() : 'Unknown'

    // Extract all key-value rows
    const rows = []
    const rowRegex = /<span class="f-k">([\s\S]*?)<\/span>[\s\S]*?<span class="f-v">([\s\S]*?)<\/span>/gi
    let rowMatch
    while ((rowMatch = rowRegex.exec(block)) !== null) {
      const key = stripTags(rowMatch[1]).trim()
      const val = stripTags(rowMatch[2]).trim()
      if (key && val) rows.push(`${key}: ${val}`)
    }

    findings.push({
      type,
      detail: rows.join('\n'),
      raw: type + (rows.length ? '\n' + rows.join('\n') : '')
    })
  }
  return findings
}

function stripTags(html) {
  return html.replace(/<[^>]*>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
}

/**
 * Check if gemma4:31b is loaded in Ollama VRAM. Returns status object.
 */
async function checkModelStatus(env) {
  try {
    const resp = await fetch(env.AI_TUNNEL_URL + '/api/ps', {
      headers: { 'X-API-Key': env.AI_API_KEY },
      signal: AbortSignal.timeout(10_000)
    })
    if (!resp.ok) return { loaded: false, status: 'unreachable' }
    const data = await resp.json()
    const models = data.models || []
    const gemma = models.find(m => m.name && m.name.includes('gemma4'))
    return gemma ? { loaded: true, status: 'ready', model: gemma.name } : { loaded: false, status: 'not_loaded' }
  } catch (e) {
    return { loaded: false, status: 'error', error: e.message }
  }
}

/**
 * Warm up the model. Sends a load request, then polls /api/ps until the model appears.
 * Handles Cloudflare 524 timeouts gracefully since model loading can exceed CF's timeout.
 */
async function warmUpModel(env) {
  // Fire the load request — don't wait for it to complete (CF may 524 it)
  fetch(env.AI_TUNNEL_URL + '/api/generate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': env.AI_API_KEY
    },
    body: JSON.stringify({ model: 'gemma4:31b', prompt: '', keep_alive: -1 }),
    signal: AbortSignal.timeout(300_000)
  }).catch(() => {}) // ignore errors — we'll poll instead

  // Poll /api/ps every 10 seconds until model is loaded (max 3 minutes)
  const maxWait = 180_000
  const interval = 10_000
  const start = Date.now()
  while (Date.now() - start < maxWait) {
    await new Promise(r => setTimeout(r, interval))
    const status = await checkModelStatus(env)
    if (status.loaded) return
  }
  throw new Error('Model did not load within 3 minutes')
}

/**
 * Call Ollama via Cloudflare Tunnel to verify a single finding. Retries once on timeout.
 */
async function verifyOneFinding(finding, env) {
  const userPrompt = `REFERENCE ARTICLE:\n${ARTICLE_CONTEXT}\n\nSCANNER FINDING (Category: ${finding.type}):\n${finding.raw}\n\nEvaluate this finding. Is it related to the Axios supply chain attack described above, or is it a false positive?`

  const body = JSON.stringify({
    model: 'gemma4:31b',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: userPrompt }
    ],
    stream: false,
    think: false,
    options: { temperature: 0.1, num_predict: 1000 }
  })

  async function attempt() {
    const resp = await fetch(env.AI_TUNNEL_URL + '/api/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': env.AI_API_KEY
      },
      body,
      signal: AbortSignal.timeout(180_000) // 3 minutes
    })

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '')
      if (errText.includes('loading model')) {
        throw new Error('MODEL_LOADING')
      }
      throw new Error(`Ollama returned ${resp.status}`)
    }

    return await resp.json()
  }

  // Try once, if timeout or model loading, retry after brief wait
  let data
  try {
    data = await attempt()
  } catch (e) {
    if (e.message === 'MODEL_LOADING' || e.name === 'TimeoutError' || e.message.includes('aborted')) {
      // Retry once after waiting for model
      await new Promise(r => setTimeout(r, 5000))
      data = await attempt()
    } else {
      throw e
    }
  }

  let text = (data.message?.content || '').trim()

  // Strip <think>...</think> blocks (Gemma/Qwen thinking mode)
  text = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim()

  // Parse verdict
  let verdict = 'Unknown'
  let reason = ''
  const primary = text.match(/VERDICT:\s*(Confirmed|Likely|Unlikely|FalsePositive)\s*\|\s*REASON:\s*(.+)/i)
  if (primary) {
    verdict = primary[1]
    reason = primary[2].trim()
  } else {
    const fallback = text.match(/(Confirmed|Likely|Unlikely|FalsePositive)/i)
    if (fallback) {
      verdict = fallback[1]
      reason = text
    }
  }

  return { verdict, reason }
}

/**
 * Verify all findings for a submission. Returns summary.
 */
async function verifySubmissionFindings(submissionId, env) {
  // Get the report HTML from R2
  const row = await env.DB.prepare('SELECT report_key FROM submissions WHERE id = ?')
    .bind(submissionId).first()
  if (!row) throw new Error('Submission not found')

  const obj = await env.BUCKET.get(row.report_key)
  if (!obj) throw new Error('Report not found in storage')

  const html = await obj.text()
  const findings = extractFindings(html)

  if (findings.length === 0) {
    // No findings — mark as AI_CLEAN
    await env.DB.prepare('UPDATE submissions SET ai_verdict = ? WHERE id = ?')
      .bind('AI_CLEAN', submissionId).run()
    return { ai_verdict: 'AI_CLEAN', findings_verified: 0, findings_total: 0 }
  }

  // Clear any previous AI verdicts for this submission
  await env.DB.prepare('DELETE FROM finding_ai_verdicts WHERE submission_id = ?')
    .bind(submissionId).run()

  let confirmed = 0, likely = 0, unlikely = 0, falsePositive = 0, errors = 0
  const now = new Date().toISOString()

  // Process findings sequentially to avoid overwhelming the GPU
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i]
    let verdict = 'Error'
    let reason = ''

    try {
      const result = await verifyOneFinding(finding, env)
      verdict = result.verdict
      reason = result.reason
    } catch (e) {
      const isTimeout = e.name === 'TimeoutError' || e.message.includes('aborted') || e.message.includes('timeout')
      verdict = isTimeout ? 'TimedOut' : 'Error'
      reason = isTimeout ? 'AI evaluation timed out — click Re-Evaluate to retry' : `AI verification failed: ${e.message}`
      errors++
    }

    // Tally
    if (verdict === 'Confirmed') confirmed++
    else if (verdict === 'Likely') likely++
    else if (verdict === 'Unlikely') unlikely++
    else if (verdict === 'FalsePositive') falsePositive++

    // Store per-finding verdict
    await env.DB.prepare(`
      INSERT INTO finding_ai_verdicts (id, submission_id, finding_index, category, description, verdict, reason, verified_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(), submissionId, i, finding.type,
      finding.detail.slice(0, 500), verdict, reason, now
    ).run()
  }

  // Compute aggregate verdict
  let aiVerdict = null
  if (errors === findings.length) {
    aiVerdict = null // all failed — leave as unreviewed
  } else if (confirmed > 0 || likely > 0) {
    aiVerdict = 'AI_COMPROMISE'
  } else if (errors > 0) {
    aiVerdict = 'AI_PARTIAL' // some succeeded, some timed out — needs re-evaluation
  } else {
    aiVerdict = 'AI_FALSE_POSITIVE'
  }

  await env.DB.prepare('UPDATE submissions SET ai_verdict = ? WHERE id = ?')
    .bind(aiVerdict, submissionId).run()

  return {
    ai_verdict: aiVerdict,
    findings_verified: findings.length - errors,
    findings_total: findings.length,
    breakdown: { confirmed, likely, unlikely, falsePositive, errors }
  }
}

/**
 * POST /api/submissions/:id/ai-verify — admin triggers AI evaluation for one submission
 */
export async function handleAiVerify(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  // Check AI is configured
  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ error: 'AI verification not configured' }, 503)
  }

  // Verify submission exists
  const sub = await env.DB.prepare('SELECT id, verdict FROM submissions WHERE id = ?')
    .bind(submissionId).first()
  if (!sub) return json({ error: 'Submission not found' }, 404)

  try {
    const result = await verifySubmissionFindings(submissionId, env)
    return json(result)
  } catch (e) {
    return json({ error: `AI verification failed: ${e.message}` }, 500)
  }
}

/**
 * GET /api/submissions/:id/ai-verdicts — returns per-finding AI verdicts
 */
export async function handleGetAiVerdicts(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const rows = await env.DB.prepare(
      'SELECT finding_index, category, description, verdict, reason, verified_at FROM finding_ai_verdicts WHERE submission_id = ? ORDER BY finding_index ASC'
    ).bind(submissionId).all()
    return json({ verdicts: rows.results ?? [] })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

/**
 * GET /api/ai-status — check if AI model is loaded and ready
 */
export async function handleAiStatus(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ loaded: false, status: 'not_configured' })
  }

  const status = await checkModelStatus(env)
  return json(status)
}

/**
 * POST /api/ai-warmup — trigger model load if not loaded
 */
export async function handleAiWarmup(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ error: 'AI not configured' }, 503)
  }

  try {
    await warmUpModel(env)
    return json({ status: 'ready' })
  } catch (e) {
    return json({ error: e.message, status: 'failed' }, 500)
  }
}

/**
 * POST /api/ai-verify-all — bulk evaluate all unreviewed submissions (background)
 */
export async function handleAiVerifyAll(request, env, ctx) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  if (!env.AI_TUNNEL_URL || !env.AI_API_KEY) {
    return json({ error: 'AI verification not configured' }, 503)
  }

  // Find unreviewed submissions
  const rows = await env.DB.prepare(
    "SELECT id FROM submissions WHERE ai_verdict IS NULL AND verdict = 'COMPROMISED' ORDER BY submitted_at DESC"
  ).all()

  const ids = (rows.results ?? []).map(r => r.id)
  if (ids.length === 0) return json({ queued: 0, message: 'No submissions to evaluate' })

  // Process in background so we can return immediately
  ctx.waitUntil((async () => {
    for (const id of ids) {
      try {
        await verifySubmissionFindings(id, env)
      } catch { /* continue to next */ }
    }
  })())

  return json({ queued: ids.length })
}
