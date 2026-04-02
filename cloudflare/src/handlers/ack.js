import { json, checkAdminPassword } from '../util.js'

export async function handleGetAcks(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const rows = await env.DB.prepare(
      'SELECT finding_hash, reason, acknowledged_at FROM finding_acknowledgements WHERE submission_id = ? ORDER BY acknowledged_at ASC'
    ).bind(submissionId).all()

    return json({ acks: rows.results ?? [] })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handlePostAck(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  let body
  try { body = await request.json() } catch { return json({ error: 'Invalid JSON' }, 400) }

  const { finding_hash, reason } = body ?? {}
  if (!finding_hash) return json({ error: 'Missing finding_hash' }, 400)
  if (!reason || !String(reason).trim()) return json({ error: 'Reason is required' }, 400)

  const id  = crypto.randomUUID()
  const now = new Date().toISOString()

  try {
    await env.DB.prepare(
      'INSERT INTO finding_acknowledgements (id, submission_id, finding_hash, reason, acknowledged_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(id, submissionId, finding_hash, String(reason).trim(), now).run()

    return json({ ok: true, id, acknowledged_at: now }, 201)
  } catch (e) {
    if (String(e).includes('UNIQUE')) return json({ error: 'Already acknowledged' }, 409)
    return json({ error: 'Database error' }, 500)
  }
}
