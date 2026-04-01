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
  return new Response('not implemented', { status: 501 })
}
