export async function handleUserReport(request, env, id, type) {
  const url      = new URL(request.url)
  const username = (url.searchParams.get('username') || '').trim()

  if (!username) {
    return new Response('Bad Request', { status: 400, headers: { 'Content-Type': 'text/plain' } })
  }

  try {
    const row = await env.DB.prepare(
      'SELECT brief_key, report_key, username FROM submissions WHERE id = ?'
    ).bind(id).first()

    if (!row) return notFound()

    // Ownership check — case-insensitive to handle Windows username casing
    if (row.username.toLowerCase() !== username.toLowerCase()) {
      return notFound()
    }

    const key = type === 'brief' ? row.brief_key : row.report_key
    const obj = await env.BUCKET.get(key)
    if (!obj) return notFound()

    let html = await obj.text()

    const label   = type === 'brief' ? 'EXECUTIVE BRIEFING' : 'TECHNICAL REPORT'
    const backBar = `<div style="position:sticky;top:0;z-index:9999;background:#1a1a1a;border-bottom:1px solid #333;padding:8px 20px;font-family:'Courier New',monospace;display:flex;align-items:center;gap:12px">`
      + `<button onclick="window.close()" style="background:#00ff41;color:#0f0f0f;border:none;padding:5px 14px;font-family:monospace;font-size:0.82rem;font-weight:bold;cursor:pointer;letter-spacing:1px">&larr; BACK TO MY SCANS</button>`
      + `<span style="color:#555;font-size:0.75rem">${label} &mdash; READ ONLY</span>`
      + `</div>`

    html = html.includes('<body')
      ? html.replace(/(<body[^>]*>)/, '$1' + backBar)
      : backBar + html

    if (type === 'brief') {
      const safeId      = id.replace(/[^a-zA-Z0-9\-_]/g, '')
      const reportOrigin = new URL(request.url).origin
      const encodedUser = encodeURIComponent(username)

      const script = `<script>
function _rcViewFull(){
  fetch('${reportOrigin}/ratcatcher/api/user-report/${safeId}/full?username=${encodedUser}')
    .then(function(r){return r.ok?r.blob():Promise.reject(r.status)})
    .then(function(b){window.open(URL.createObjectURL(b),'_blank')})
    .catch(function(e){alert('Failed to load report ('+e+')')})
}
<\/script>`

      html = html.replace('</head>', script + '</head>')
      html = html.replace(
        /<div class="rc-links">[\s\S]*?<\/div>/,
        '<div class="rc-links"><a class="rc-link" href="#" onclick="_rcViewFull();return false">&#128202; Technical Forensic Report</a></div>'
      )
      html = html.replace(
        /(<span class="meta-k">Technical Report<\/span><span class="meta-v">)<a href="[^"]*">/g,
        '$1<a href="#" onclick="_rcViewFull();return false">'
      )
    }

    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
  } catch {
    return new Response('Internal Server Error', { status: 500, headers: { 'Content-Type': 'text/plain' } })
  }
}

function notFound() {
  return new Response(
    '<!DOCTYPE html><html><head><title>Not Found</title></head><body style="background:#0f0f0f;color:#ccc;font-family:monospace;padding:40px"><h2>Report not available</h2><p>This report was not found or you do not have access to it.</p></body></html>',
    { status: 404, headers: { 'Content-Type': 'text/html' } }
  )
}
