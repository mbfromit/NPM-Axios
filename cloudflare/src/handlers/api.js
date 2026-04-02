import { json, checkAdminPassword } from '../util.js'

export async function handleSubmissions(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  const url    = new URL(request.url)
  const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1',  10) || 1)
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 1))
  const offset = (page - 1) * limit

  try {
    const countRow = await env.DB.prepare(
      'SELECT COUNT(*) AS total FROM submissions'
    ).first()
    const total = countRow?.total ?? 0

    const rows = await env.DB.prepare(`
      SELECT id, hostname, username, submitted_at, verdict, duration,
             projects_scanned, vulnerable_count, critical_count
      FROM submissions
      ORDER BY submitted_at DESC
      LIMIT ? OFFSET ?
    `).bind(limit, offset).all()

    return json({ total, page, limit, submissions: rows.results })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleStats(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const row = await env.DB.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN verdict = 'CLEAN'       THEN 1 ELSE 0 END) AS clean,
        SUM(CASE WHEN verdict = 'COMPROMISED' THEN 1 ELSE 0 END) AS compromised
      FROM submissions
    `).first()

    return json({
      total:       row?.total       ?? 0,
      clean:       row?.clean       ?? 0,
      compromised: row?.compromised ?? 0
    })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleReport(request, env, id, type) {
  if (!checkAdminPassword(request, env)) {
    return new Response('Unauthorized', { status: 401, headers: { 'Content-Type': 'text/plain' } })
  }

  try {
    const row = await env.DB.prepare(
      'SELECT brief_key, report_key FROM submissions WHERE id = ?'
    ).bind(id).first()

    if (!row) return notFound()

    const key = type === 'brief' ? row.brief_key : row.report_key
    const obj = await env.BUCKET.get(key)
    if (!obj) return notFound()

    let html = await obj.text()

    const backBar = `<div style="position:sticky;top:0;z-index:9999;background:#1a1a1a;border-bottom:1px solid #333;padding:8px 20px;font-family:'Courier New',monospace;display:flex;align-items:center;gap:12px">` +
      `<button onclick="window.close()" style="background:#00ff41;color:#0f0f0f;border:none;padding:5px 14px;font-family:monospace;font-size:0.82rem;font-weight:bold;cursor:pointer;letter-spacing:1px">&larr; BACK TO DASHBOARD</button>` +
      `<span style="color:#555;font-size:0.75rem">${type === 'brief' ? 'EXECUTIVE BRIEFING' : 'TECHNICAL REPORT'}</span></div>`
    html = html.includes('<body')
      ? html.replace(/(<body[^>]*>)/, '$1' + backBar)
      : backBar + html

    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
  } catch {
    return new Response('Internal Server Error', { status: 500, headers: { 'Content-Type': 'text/plain' } })
  }
}

export async function handleDeleteSubmission(request, env, id) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const row = await env.DB.prepare(
      'SELECT brief_key, report_key FROM submissions WHERE id = ?'
    ).bind(id).first()

    if (!row) return json({ error: 'Not found' }, 404)

    await env.DB.prepare('DELETE FROM submissions WHERE id = ?').bind(id).run()

    try {
      await env.BUCKET.delete(row.brief_key)
      await env.BUCKET.delete(row.report_key)
    } catch { /* best-effort R2 cleanup */ }

    return json({ deleted: id })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

function notFound() {
  return new Response(
    '<!DOCTYPE html><html><head><title>Not Found</title></head><body style="background:#0f0f0f;color:#ccc;font-family:monospace;padding:40px"><h2>Report no longer available</h2><p>This report has been removed or has expired.</p></body></html>',
    { status: 404, headers: { 'Content-Type': 'text/html' } }
  )
}
