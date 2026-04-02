import { json, checkAdminPassword } from '../util.js'

export async function handleSubmissions(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  const url    = new URL(request.url)
  const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1',  10) || 1)
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 1))
  const offset = (page - 1) * limit
  const verdict = url.searchParams.get('verdict')
  const validVerdicts = ['CLEAN', 'COMPROMISED']
  const filterVerdict = validVerdicts.includes(verdict) ? verdict : null
  const search = (url.searchParams.get('search') || '').trim()

  try {
    const conditions = []
    const binds = []
    if (filterVerdict) { conditions.push('verdict = ?'); binds.push(filterVerdict) }
    if (search) { conditions.push('(hostname LIKE ? OR username LIKE ?)'); binds.push('%'+search+'%', '%'+search+'%') }
    const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : ''

    const countStmt = env.DB.prepare('SELECT COUNT(*) AS total FROM submissions' + where)
    const countRow = await (binds.length ? countStmt.bind(...binds) : countStmt).first()
    const total = countRow?.total ?? 0

    const rowsStmt = env.DB.prepare(`
      SELECT s.*, CASE WHEN s.submitted_at = latest.max_at THEN 1 ELSE 0 END AS is_latest
      FROM (
        SELECT id, hostname, username, submitted_at, verdict, duration,
               projects_scanned, vulnerable_count, critical_count
        FROM submissions${where}
        ORDER BY submitted_at DESC
        LIMIT ? OFFSET ?
      ) s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
    `)
    const rows = await rowsStmt.bind(...binds, limit, offset).all()

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
      'SELECT brief_key, report_key, findings_count FROM submissions WHERE id = ?'
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

    if (type === 'brief') {
      const script = `<script>
function _rcViewFull(){
  try{if(window.opener&&window.opener.vw){window.opener.vw('${id}','full');return}}catch(e){}
  var pw=prompt('Admin password:','');
  if(!pw)return;
  fetch('/ratcatcher/api/report/${id}/full',{headers:{'X-Admin-Password':pw}})
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

    if (type === 'full') {
      // Count findings and persist if not yet stored
      if (!row.findings_count) {
        const matches = html.match(/<div class="finding /g)
        const count = matches ? matches.length : 0
        if (count > 0) {
          try {
            await env.DB.prepare('UPDATE submissions SET findings_count = ? WHERE id = ?')
              .bind(count, id).run()
          } catch { /* non-fatal */ }
        }
      }

      // Inject ack styles
      const ackStyles = `<style>
.rc-ack-btn{background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:4px 12px;cursor:pointer;font-family:'Consolas',monospace;font-size:11px;border-radius:3px;margin-top:10px;display:block}
.rc-ack-btn:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.rc-ack-done{display:flex;align-items:flex-start;gap:8px;margin-top:10px;padding:8px 10px;background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);border-radius:3px}
.rc-ack-check{color:#3fb950;font-size:14px;flex-shrink:0;margin-top:1px}
.rc-ack-info{display:flex;flex-direction:column;gap:2px}
.rc-ack-label{font-size:10px;font-weight:700;letter-spacing:1px;color:#3fb950;font-family:'Consolas',monospace}
.rc-ack-reason{font-size:11px;color:#8b949e;font-family:'Consolas',monospace;word-break:break-word}
.rc-ack-when{font-size:10px;color:#484f58;font-family:'Consolas',monospace}
.rc-modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:10000;align-items:center;justify-content:center}
.rc-modal-overlay.open{display:flex}
.rc-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:28px;width:480px;max-width:90vw}
.rc-modal h3{color:#58a6ff;font-family:'Consolas',monospace;font-size:13px;letter-spacing:2px;margin-bottom:6px}
.rc-modal p{color:#6e7681;font-size:12px;margin-bottom:16px;line-height:1.5}
.rc-modal textarea{width:100%;background:#06090f;border:1px solid #21303f;color:#c9d1d9;font-family:'Consolas',monospace;font-size:12px;padding:10px;border-radius:4px;resize:vertical;min-height:100px;max-height:400px}
.rc-modal textarea:focus{outline:none;border-color:#58a6ff}
.rc-modal-err{color:#f85149;font-size:11px;min-height:16px;margin-top:6px;font-family:'Consolas',monospace}
.rc-modal-btns{display:flex;gap:10px;margin-top:14px;justify-content:flex-end}
.rc-modal-btns button{padding:6px 18px;font-family:'Consolas',monospace;font-size:12px;border-radius:3px;cursor:pointer}
.rc-modal-cancel{background:none;border:1px solid #2a2a2a;color:#6e7681}
.rc-modal-cancel:hover{border-color:#555;color:#ccc}
.rc-modal-save{background:#238636;border:1px solid #2ea043;color:#fff;font-weight:bold}
.rc-modal-save:hover{background:#2ea043}
</style>`

      // Inject ack script
      const ackScript = `<script>
(function(){
  var SUB='${id}',B='/ratcatcher',PW='';
  try{PW=window.opener&&window.opener.pw||'';}catch(e){}

  function getHeaders(){return{'X-Admin-Password':PW,'Content-Type':'application/json'}}

  // Modal
  var overlay=document.createElement('div');
  overlay.className='rc-modal-overlay';
  overlay.innerHTML='<div class="rc-modal">'
    +'<h3>ACKNOWLEDGE FINDING</h3>'
    +'<p id="rc-m-path" style="color:#e6edf3;font-family:monospace;font-size:11px;margin-bottom:10px;word-break:break-all"></p>'
    +'<p>Provide a reason why this finding is benign or not applicable. Be specific — this record is kept for audit purposes.</p>'
    +'<textarea id="rc-m-reason" placeholder="e.g. .NET shadow copy cache from Solutions clinical app — not RAT-related. Verified by jsmith 2026-04-02."></textarea>'
    +'<div class="rc-modal-err" id="rc-m-err"></div>'
    +'<div class="rc-modal-btns">'
    +'<button class="rc-modal-cancel" id="rc-m-cancel">Cancel</button>'
    +'<button class="rc-modal-save" id="rc-m-save">Save Acknowledgement</button>'
    +'</div></div>';
  document.body.appendChild(overlay);

  var currentHash=null,currentEl=null;
  document.getElementById('rc-m-cancel').onclick=function(){overlay.classList.remove('open')};
  overlay.onclick=function(e){if(e.target===overlay)overlay.classList.remove('open')};
  document.getElementById('rc-m-save').onclick=saveAck;

  function openModal(hash,el,pathText){
    currentHash=hash;currentEl=el;
    document.getElementById('rc-m-path').textContent=pathText;
    document.getElementById('rc-m-reason').value='';
    document.getElementById('rc-m-err').textContent='';
    overlay.classList.add('open');
    setTimeout(function(){document.getElementById('rc-m-reason').focus()},50);
  }

  function saveAck(){
    var reason=document.getElementById('rc-m-reason').value.trim();
    if(!reason){document.getElementById('rc-m-err').textContent='Reason is required.';return;}
    document.getElementById('rc-m-save').disabled=true;
    document.getElementById('rc-m-save').textContent='Saving...';
    fetch(B+'/api/submissions/'+SUB+'/acks',{
      method:'POST',
      headers:getHeaders(),
      body:JSON.stringify({finding_hash:currentHash,reason:reason})
    })
    .then(function(r){return r.json().then(function(b){return{status:r.status,body:b}})})
    .then(function(res){
      document.getElementById('rc-m-save').disabled=false;
      document.getElementById('rc-m-save').textContent='Save Acknowledgement';
      if(res.status===201||res.status===409){
        overlay.classList.remove('open');
        markAcked(currentEl,reason,res.body.acknowledged_at||new Date().toISOString());
      } else {
        document.getElementById('rc-m-err').textContent=res.body.error||'Save failed.';
      }
    })
    .catch(function(){
      document.getElementById('rc-m-save').disabled=false;
      document.getElementById('rc-m-save').textContent='Save Acknowledgement';
      document.getElementById('rc-m-err').textContent='Network error — please try again.';
    });
  }

  function markAcked(el,reason,when){
    var btn=el.querySelector('.rc-ack-btn');
    if(btn)btn.remove();
    if(el.querySelector('.rc-ack-done'))return;
    var d=document.createElement('div');
    d.className='rc-ack-done';
    var ts=when?new Date(when).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'}):'';
    d.innerHTML='<span class="rc-ack-check">&#10003;</span>'
      +'<div class="rc-ack-info">'
      +'<span class="rc-ack-label">ACKNOWLEDGED</span>'
      +'<span class="rc-ack-reason">'+esc(reason)+'</span>'
      +(ts?'<span class="rc-ack-when">'+esc(ts)+'</span>':'')
      +'</div>';
    el.appendChild(d);
  }

  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

  async function hashFinding(type,path){
    var text=type+'|'+path;
    var buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
  }

  function getPathFromFinding(el){
    var rows=el.querySelectorAll('.f-row');
    for(var i=0;i<rows.length;i++){
      var k=rows[i].querySelector('.f-k');
      if(k&&(k.textContent.trim()==='PATH'||k.textContent.trim()==='LOCATION')){
        var v=rows[i].querySelector('.f-v');
        return v?v.textContent.trim():'';
      }
    }
    return '';
  }

  async function initFindings(acksMap){
    var findings=document.querySelectorAll('.finding');
    for(var i=0;i<findings.length;i++){
      var el=findings[i];
      var typeEl=el.querySelector('.f-type');
      var type=typeEl?typeEl.textContent.trim():'';
      var path=getPathFromFinding(el);
      var hash=await hashFinding(type,path);
      el.dataset.fhash=hash;
      if(acksMap[hash]){
        markAcked(el,acksMap[hash].reason,acksMap[hash].acknowledged_at);
      } else {
        var btn=document.createElement('button');
        btn.className='rc-ack-btn';
        btn.textContent='Acknowledge Finding';
        btn.dataset.hash=hash;
        (function(h,element,p){
          btn.onclick=function(){openModal(h,element,p)};
        })(hash,el,path||type);
        el.appendChild(btn);
      }
    }
  }

  // Load existing acks then init
  fetch(B+'/api/submissions/'+SUB+'/acks',{headers:{'X-Admin-Password':PW}})
    .then(function(r){return r.ok?r.json():Promise.resolve({acks:[]})})
    .then(function(data){
      var map={};
      (data.acks||[]).forEach(function(a){map[a.finding_hash]=a});
      initFindings(map);
    })
    .catch(function(){initFindings({})});
})();
<\/script>`

      html = html.replace('</head>', ackStyles + '</head>')
      html = html.replace('</body>', ackScript + '</body>')
    }

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

export async function handleExport(request, env) {
  if (!checkAdminPassword(request, env)) return json({ error: 'Unauthorized' }, 401)

  try {
    const rows = await env.DB.prepare(`
      SELECT hostname, username, submitted_at, verdict, duration,
             projects_scanned, vulnerable_count, critical_count
      FROM submissions
      ORDER BY submitted_at DESC
    `).all()

    const header = 'Hostname,Username,Submitted,Verdict,Duration,Projects Scanned,Vulnerable Count,Critical Count'
    const csvRows = (rows.results || []).map(r => {
      const fields = [r.hostname, r.username, r.submitted_at, r.verdict, r.duration,
                      r.projects_scanned, r.vulnerable_count, r.critical_count]
      return fields.map(f => '"' + String(f ?? '').replace(/"/g, '""') + '"').join(',')
    })
    const csv = header + '\n' + csvRows.join('\n')

    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="ratcatcher-export.csv"'
      }
    })
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
