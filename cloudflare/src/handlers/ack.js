import { json, checkAdminPassword } from '../util.js'

export async function handleUpdateFindingsCount(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  let body
  try { body = await request.json() } catch { return json({ error: 'Invalid JSON' }, 400) }

  const count = body?.count
  if (typeof count !== 'number' || count < 0) return json({ error: 'Invalid count' }, 400)

  try {
    await env.DB.prepare('UPDATE submissions SET findings_count = ? WHERE id = ?')
      .bind(count, submissionId).run()
    return json({ ok: true, findings_count: count })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleGetAcks(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const rows = await env.DB.prepare(
      'SELECT finding_hash, reason, acknowledged_at, is_threat FROM finding_acknowledgements WHERE submission_id = ? ORDER BY acknowledged_at ASC'
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

  const { finding_hash, reason, is_threat } = body ?? {}
  if (!finding_hash) return json({ error: 'Missing finding_hash' }, 400)
  if (!reason || !String(reason).trim()) return json({ error: 'Reason is required' }, 400)

  const id  = crypto.randomUUID()
  const now = new Date().toISOString()
  const threat = is_threat ? 1 : 0

  try {
    await env.DB.prepare(
      'INSERT INTO finding_acknowledgements (id, submission_id, finding_hash, reason, acknowledged_at, is_threat) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(id, submissionId, finding_hash, String(reason).trim(), now, threat).run()

    return json({ ok: true, id, acknowledged_at: now, is_threat: threat }, 201)
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      // Update existing ack if changing to/from threat
      try {
        await env.DB.prepare(
          'UPDATE finding_acknowledgements SET reason = ?, is_threat = ?, acknowledged_at = ? WHERE submission_id = ? AND finding_hash = ?'
        ).bind(String(reason).trim(), threat, now, submissionId, finding_hash).run()
        return json({ ok: true, acknowledged_at: now, is_threat: threat, updated: true }, 200)
      } catch { return json({ error: 'Database error' }, 500) }
    }
    return json({ error: 'Database error' }, 500)
  }
}

export async function handleCertify(request, env, submissionId) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  let body
  try { body = await request.json() } catch { return json({ error: 'Invalid JSON' }, 400) }

  const name = (body?.certified_by || '').trim()
  if (!name) return json({ error: 'Manager name is required' }, 400)
  if (name.split(/\s+/).length < 2) return json({ error: 'Please enter first and last name' }, 400)

  const now = new Date().toISOString()

  try {
    const row = await env.DB.prepare('SELECT ai_verdict FROM submissions WHERE id = ?')
      .bind(submissionId).first()
    if (!row) return json({ error: 'Submission not found' }, 404)
    if (row.ai_verdict !== 'AI_COMPROMISE') return json({ error: 'Only AI-verified compromises require certification' }, 400)

    await env.DB.prepare('UPDATE submissions SET certified_by = ?, certified_at = ? WHERE id = ?')
      .bind(name, now, submissionId).run()

    return json({ ok: true, certified_by: name, certified_at: now })
  } catch {
    return json({ error: 'Database error' }, 500)
  }
}
