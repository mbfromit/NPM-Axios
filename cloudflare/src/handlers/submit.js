import { json } from '../util.js'

export async function handleSubmit(request, env) {
  let formData
  try {
    formData = await request.formData()
  } catch {
    return json({ error: 'Invalid form data' }, 400)
  }

  const password = formData.get('password')
  if (password !== env.SUBMIT_PASSWORD) {
    return json({ error: 'Unauthorized' }, 401)
  }

  for (const field of ['hostname', 'username', 'scan_timestamp', 'verdict']) {
    if (!formData.get(field)) {
      return json({ error: `Missing field: ${field}` }, 400)
    }
  }

  const briefFile  = formData.get('brief')
  const reportFile = formData.get('report')
  if (!briefFile || !reportFile) {
    return json({ error: 'Missing brief or report file' }, 400)
  }

  const MAX = 25 * 1024 * 1024
  const briefBytes  = await briefFile.arrayBuffer()
  const reportBytes = await reportFile.arrayBuffer()
  if (briefBytes.byteLength > MAX || reportBytes.byteLength > MAX) {
    return json({ error: 'File exceeds 25MB limit' }, 413)
  }

  const id        = crypto.randomUUID()
  const briefKey  = `submissions/${id}/brief.html`
  const reportKey = `submissions/${id}/report.html`

  try {
    await env.BUCKET.put(briefKey,  briefBytes,  { httpMetadata: { contentType: 'text/html' } })
    await env.BUCKET.put(reportKey, reportBytes, { httpMetadata: { contentType: 'text/html' } })
  } catch {
    return json({ error: 'Storage failure' }, 500)
  }

  try {
    await env.DB.prepare(`
      INSERT INTO submissions
        (id, hostname, username, submitted_at, scan_timestamp, duration, verdict,
         projects_scanned, vulnerable_count, critical_count, paths_scanned, brief_key, report_key)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      formData.get('hostname'),
      formData.get('username'),
      new Date().toISOString(),
      formData.get('scan_timestamp'),
      formData.get('duration')    || null,
      formData.get('verdict'),
      parseInt(formData.get('projects_scanned')) || null,
      parseInt(formData.get('vulnerable_count')) || null,
      parseInt(formData.get('critical_count'))   || null,
      formData.get('paths_scanned') || null,
      briefKey,
      reportKey
    ).run()
  } catch {
    return json({ error: 'Database failure' }, 500)
  }

  return json({ id }, 201)
}
