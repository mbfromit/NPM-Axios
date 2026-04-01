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

    if (type === 'brief') {
      const banner = `<div style="background:#dc2626;color:#fff;padding:10px 20px;font-family:monospace;font-size:13px;text-align:center;border-bottom:1px solid #991b1b">` +
        `Full Technical Report: <a href="/ratcatcher/api/report/${id}/full" style="color:#fff;font-weight:bold" target="_blank">View Full Report &rarr;</a></div>`
      html = html.includes('<body')
        ? html.replace(/(<body[^>]*>)/, '$1' + banner)
        : banner + html
    }

    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
  } catch {
    return new Response('Internal Server Error', { status: 500, headers: { 'Content-Type': 'text/plain' } })
  }
}

function notFound() {
  return new Response(
    '<!DOCTYPE html><html><head><title>Not Found</title></head><body style="background:#0f0f0f;color:#ccc;font-family:monospace;padding:40px"><h2>Report no longer available</h2><p>This report has been removed or has expired.</p></body></html>',
    { status: 404, headers: { 'Content-Type': 'text/html' } }
  )
}
