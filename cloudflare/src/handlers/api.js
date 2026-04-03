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
  const reviewed = url.searchParams.get('reviewed')
  const filterReviewed = reviewed === '1' || reviewed === '0' ? reviewed : null
  const positive = url.searchParams.get('positive')

  try {
    const conditions = []
    const binds = []
    if (filterVerdict) { conditions.push('verdict = ?'); binds.push(filterVerdict) }
    if (search) { conditions.push('(hostname LIKE ? OR username LIKE ?)'); binds.push('%'+search+'%', '%'+search+'%') }
    if (positive === '1') {
      conditions.push('(SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) > 0')
    } else if (filterReviewed === '1') {
      conditions.push('findings_count > 0 AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) >= findings_count AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) = 0')
    } else if (filterReviewed === '0') {
      conditions.push('(findings_count IS NULL OR findings_count = 0 OR (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) < findings_count)')
    }
    const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : ''

    const countStmt = env.DB.prepare('SELECT COUNT(*) AS total FROM submissions' + where)
    const countRow = await (binds.length ? countStmt.bind(...binds) : countStmt).first()
    const total = countRow?.total ?? 0

    const rowsStmt = env.DB.prepare(`
      SELECT s.*,
        CASE WHEN s.submitted_at = latest.max_at THEN 1 ELSE 0 END AS is_latest,
        COALESCE(ac.ack_count, 0) AS ack_count,
        COALESCE(tc.threat_count, 0) AS threat_count,
        CASE WHEN COALESCE(tc.threat_count, 0) > 0 THEN 1 ELSE 0 END AS positive,
        CASE WHEN COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0 AND COALESCE(ac.ack_count, 0) >= s.findings_count THEN 1 ELSE 0 END AS reviewed
      FROM (
        SELECT id, hostname, username, submitted_at, verdict, duration,
               projects_scanned, vulnerable_count, critical_count, findings_count
        FROM submissions${where}
        ORDER BY submitted_at DESC
        LIMIT ? OFFSET ?
      ) s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
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
        SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) AS clean,
        SUM(CASE WHEN COALESCE(tc.threat_count, 0) > 0 THEN 1 ELSE 0 END) AS positive,
        SUM(CASE WHEN verdict = 'COMPROMISED'
              AND COALESCE(tc.threat_count, 0) = 0
              AND s.findings_count > 0
              AND COALESCE(ac.ack_count, 0) >= s.findings_count
             THEN 1 ELSE 0 END) AS reviewed,
        SUM(CASE WHEN verdict = 'COMPROMISED'
              AND COALESCE(tc.threat_count, 0) = 0
              AND (s.findings_count IS NULL OR s.findings_count = 0
                   OR COALESCE(ac.ack_count, 0) < s.findings_count)
             THEN 1 ELSE 0 END) AS compromised,
        SUM(CASE WHEN verdict = 'COMPROMISED'
              AND COALESCE(tc.threat_count, 0) = 0
              AND (s.findings_count IS NULL OR s.findings_count = 0
                   OR COALESCE(ac.ack_count, 0) < s.findings_count)
             THEN 1 ELSE 0 END) AS not_reviewed
      FROM submissions s
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
    `).first()

    return json({
      total:       row?.total       ?? 0,
      clean:       row?.clean       ?? 0,
      compromised: row?.compromised ?? 0,
      reviewed:    row?.reviewed    ?? 0,
      positive:    row?.positive    ?? 0,
      not_reviewed: row?.not_reviewed ?? 0
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
    const safeId = id.replace(/[^a-zA-Z0-9\-_]/g, '')

    const bulkBtns = type === 'full'
      ? `<span style="margin-left:auto;display:flex;gap:8px">`
        + `<button id="rc-bulk-ack" style="background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:5px 14px;font-family:monospace;font-size:0.82rem;cursor:pointer;letter-spacing:1px">&#9745; BULK ACKNOWLEDGE</button>`
        + `<button id="rc-bulk-threat" style="background:none;border:1px solid #5f2a2a;color:#f85149;padding:5px 14px;font-family:monospace;font-size:0.82rem;cursor:pointer;letter-spacing:1px">&#9888; BULK CONFIRM THREAT</button>`
        + `</span>`
      : ''
    const backBar = `<div style="position:sticky;top:0;z-index:9999;background:#1a1a1a;border-bottom:1px solid #333;padding:8px 20px;font-family:'Courier New',monospace;display:flex;align-items:center;gap:12px">` +
      `<button onclick="window.close()" style="background:#00ff41;color:#0f0f0f;border:none;padding:5px 14px;font-family:monospace;font-size:0.82rem;font-weight:bold;cursor:pointer;letter-spacing:1px">&larr; BACK TO DASHBOARD</button>` +
      `<span style="color:#555;font-size:0.75rem">${type === 'brief' ? 'EXECUTIVE BRIEFING' : 'TECHNICAL REPORT'}</span>${bulkBtns}</div>`
    html = html.includes('<body')
      ? html.replace(/(<body[^>]*>)/, '$1' + backBar)
      : backBar + html

    const reportOrigin = new URL(request.url).origin
    const reportPw = (request.headers.get('X-Admin-Password') || '').replace(/[\\'"]/g, '')

    if (type === 'brief') {
      const script = `<script>
function _rcViewFull(){
  try{if(window.opener&&window.opener.vw){window.opener.vw('${safeId}','full');return}}catch(e){}
  var pw='${reportPw}'||prompt('Admin password:','');
  if(!pw)return;
  fetch('${reportOrigin}/ratcatcher/api/report/${safeId}/full',{headers:{'X-Admin-Password':pw}})
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
        const matches = html.match(/<div class=["']finding["' ]/g)
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
.rc-ack-btns{display:flex;gap:8px;margin-top:10px}
.rc-ack-btn{background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:4px 12px;cursor:pointer;font-family:'Consolas',monospace;font-size:11px;border-radius:3px;display:block}
.rc-ack-btn:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.rc-threat-btn{background:none;border:1px solid #5f2a2a;color:#f85149;padding:4px 12px;cursor:pointer;font-family:'Consolas',monospace;font-size:11px;border-radius:3px;display:block}
.rc-threat-btn:hover{border-color:#f85149;background:rgba(248,81,73,.08)}
.rc-ack-done{display:flex;align-items:flex-start;gap:8px;margin-top:10px;padding:8px 10px;background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);border-radius:3px}
.rc-ack-done.threat{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.25)}
.rc-ack-check{color:#3fb950;font-size:14px;flex-shrink:0;margin-top:1px}
.rc-ack-done.threat .rc-ack-check{color:#f85149}
.rc-ack-info{display:flex;flex-direction:column;gap:2px}
.rc-ack-label{font-size:10px;font-weight:700;letter-spacing:1px;color:#3fb950;font-family:'Consolas',monospace}
.rc-ack-done.threat .rc-ack-label{color:#f85149}
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
.rc-modal.bulk h3{color:#58a6ff}
.rc-modal.bulk .rc-modal-save{background:#1f6feb;border-color:#388bfd}
.rc-modal.bulk .rc-modal-save:hover{background:#388bfd}
.rc-bulk-progress{font-size:11px;color:#8b949e;font-family:'Consolas',monospace;margin-top:8px;min-height:16px}
.rc-modal.threat h3{color:#f85149}
.rc-modal.threat .rc-modal-save{background:#da3633;border-color:#f85149}
.rc-modal.threat .rc-modal-save:hover{background:#f85149}
.rc-modal.threat textarea:focus{border-color:#f85149}
.rc-modal-save-threat{background:#da3633;border-color:#f85149}
.rc-modal-save-threat:hover{background:#f85149}
.rc-ack-actions{display:flex;gap:10px;margin-top:5px}
.rc-ack-edit{background:none;border:none;padding:0;cursor:pointer;font-family:'Consolas',monospace;font-size:10px;letter-spacing:1px;color:#58a6ff}
.rc-ack-edit:hover{text-decoration:underline}
.rc-ack-undo{background:none;border:none;padding:0;cursor:pointer;font-family:'Consolas',monospace;font-size:10px;letter-spacing:1px;color:#484f58}
.rc-ack-undo:hover{color:#f85149;text-decoration:underline}
</style>`

      // Inject ack script — use absolute URL so it works from blob: origins
      const ackScript = `<script>
(function(){
  var SUB='${safeId}',B='${reportOrigin}/ratcatcher',PW='${reportPw}';

  function getHeaders(){return{'X-Admin-Password':PW,'Content-Type':'application/json'}}

  // Modal
  var overlay=document.createElement('div');
  overlay.className='rc-modal-overlay';
  overlay.innerHTML='<div class="rc-modal" id="rc-m-dialog">'
    +'<h3 id="rc-m-title">ACKNOWLEDGE FINDING</h3>'
    +'<p id="rc-m-path" style="color:#e6edf3;font-family:monospace;font-size:11px;margin-bottom:10px;word-break:break-all"></p>'
    +'<p id="rc-m-desc">Provide a reason why this finding is benign or not applicable. Be specific — this record is kept for audit purposes.</p>'
    +'<textarea id="rc-m-reason" placeholder="e.g. .NET shadow copy cache from Solutions clinical app — not RAT-related. Verified by jsmith 2026-04-02."></textarea>'
    +'<div class="rc-modal-err" id="rc-m-err"></div>'
    +'<div class="rc-modal-btns" id="rc-m-btns-normal">'
    +'<button class="rc-modal-cancel" id="rc-m-cancel">Cancel</button>'
    +'<button class="rc-modal-save" id="rc-m-save">Save Acknowledgement</button>'
    +'</div>'
    +'<div class="rc-modal-btns" id="rc-m-btns-edit" style="display:none;flex-wrap:wrap;gap:8px">'
    +'<button class="rc-modal-cancel" id="rc-m-cancel2">Cancel</button>'
    +'<button class="rc-modal-save" id="rc-m-save-ack">&#10003; Save as Acknowledged</button>'
    +'<button class="rc-modal-save rc-modal-save-threat" id="rc-m-save-threat">&#9888; Save as Confirmed Threat</button>'
    +'</div></div>';
  document.body.appendChild(overlay);

  var currentHash=null,currentEl=null,currentThreat=false;
  function closeModal(){overlay.classList.remove('open')}
  document.getElementById('rc-m-cancel').onclick=closeModal;
  document.getElementById('rc-m-cancel2').onclick=closeModal;
  overlay.onclick=function(e){if(e.target===overlay)closeModal()};
  document.getElementById('rc-m-save').onclick=saveAck;
  document.getElementById('rc-m-save-ack').onclick=function(){saveAck(false,this)};
  document.getElementById('rc-m-save-threat').onclick=function(){saveAck(true,this)};

  function openModal(hash,el,pathText,isThreat,prefill){
    currentHash=hash;currentEl=el;currentThreat=!!isThreat;
    var isEdit=!!prefill;
    var dlg=document.getElementById('rc-m-dialog');
    dlg.className=isEdit?'rc-modal':(isThreat?'rc-modal threat':'rc-modal');
    document.getElementById('rc-m-title').textContent=isEdit?'EDIT FINDING':(isThreat?'CONFIRM THREAT':'ACKNOWLEDGE FINDING');
    document.getElementById('rc-m-desc').textContent=isEdit
      ?'Update the reason, then choose Save as Acknowledged or Save as Confirmed Threat.'
      :(isThreat?'Describe the confirmed threat. This will flag the submission as POSITIVE FINDING on the dashboard.':'Provide a reason why this finding is benign or not applicable. Be specific \u2014 this record is kept for audit purposes.');
    document.getElementById('rc-m-reason').placeholder=isThreat
      ?'e.g. Confirmed RAT beacon — C2 callback to 185.x.x.x on port 443. Escalated to IR team.'
      :'e.g. .NET shadow copy cache from Solutions clinical app \u2014 not RAT-related. Verified by jsmith 2026-04-02.';
    document.getElementById('rc-m-path').textContent=pathText;
    document.getElementById('rc-m-reason').value=prefill||'';
    document.getElementById('rc-m-err').textContent='';
    if(!isEdit)document.getElementById('rc-m-save').textContent=isThreat?'Confirm Threat':'Save Acknowledgement';
    document.getElementById('rc-m-btns-normal').style.display=isEdit?'none':'';
    document.getElementById('rc-m-btns-edit').style.display=isEdit?'flex':'none';
    overlay.classList.add('open');
    setTimeout(function(){document.getElementById('rc-m-reason').focus()},50);
  }

  function saveAck(isThreatOverride,saveBtnEl){
    var isThreat=(isThreatOverride!==undefined)?!!isThreatOverride:currentThreat;
    var reason=document.getElementById('rc-m-reason').value.trim();
    if(!reason){document.getElementById('rc-m-err').textContent='Reason is required.';return;}
    var saveBtn=saveBtnEl||document.getElementById('rc-m-save');
    var origText=saveBtn.textContent;
    saveBtn.disabled=true;
    saveBtn.textContent='Saving...';
    fetch(B+'/api/submissions/'+SUB+'/acks',{
      method:'POST',
      headers:getHeaders(),
      body:JSON.stringify({finding_hash:currentHash,reason:reason,is_threat:isThreat})
    })
    .then(function(r){return r.json().then(function(b){return{status:r.status,body:b}})})
    .then(function(res){
      saveBtn.disabled=false;
      saveBtn.textContent=origText;
      if(res.status===200||res.status===201||res.status===409){
        closeModal();
        markDone(currentEl,reason,res.body.acknowledged_at||new Date().toISOString(),isThreat,currentHash);
      } else {
        document.getElementById('rc-m-err').textContent=res.body.error||'Save failed.';
      }
    })
    .catch(function(err){
      console.error('[RatCatcher ack]',err);
      saveBtn.disabled=false;
      saveBtn.textContent=origText;
      document.getElementById('rc-m-err').textContent='Network error \u2014 please try again.';
    });
  }

  function markDone(el,reason,when,isThreat,hash){
    var btns=el.querySelector('.rc-ack-btns');
    if(btns)btns.remove();
    var old=el.querySelector('.rc-ack-done');
    if(old)old.remove();
    var d=document.createElement('div');
    d.className=isThreat?'rc-ack-done threat':'rc-ack-done';
    var ts=when?new Date(when).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'}):'';
    d.innerHTML=isThreat
      ?'<span class="rc-ack-check">&#9888;</span><div class="rc-ack-info"><span class="rc-ack-label">CONFIRMED THREAT</span><span class="rc-ack-reason">'+esc(reason)+'</span>'+(ts?'<span class="rc-ack-when">'+esc(ts)+'</span>':'')+'<div class="rc-ack-actions"></div></div>'
      :'<span class="rc-ack-check">&#10003;</span><div class="rc-ack-info"><span class="rc-ack-label">ACKNOWLEDGED</span><span class="rc-ack-reason">'+esc(reason)+'</span>'+(ts?'<span class="rc-ack-when">'+esc(ts)+'</span>':'')+'<div class="rc-ack-actions"></div></div>';
    if(hash){
      var actions=d.querySelector('.rc-ack-actions');
      var editBtn=document.createElement('button');
      editBtn.className='rc-ack-edit';
      editBtn.textContent='Edit';
      var undoBtn=document.createElement('button');
      undoBtn.className='rc-ack-undo';
      undoBtn.textContent='Undo';
      var path=getPathFromFinding(el);
      (function(h,element,p,r,t){
        editBtn.onclick=function(){openModal(h,element,p,t,r)};
        undoBtn.onclick=function(){undoAck(h,element)};
      })(hash,el,path,reason,isThreat);
      actions.appendChild(editBtn);
      actions.appendChild(undoBtn);
    }
    el.appendChild(d);
  }

  function undoAck(hash,el){
    if(!confirm('Remove this acknowledgement? The finding will return to unreviewed.'))return;
    fetch(B+'/api/submissions/'+SUB+'/acks/'+hash,{method:'DELETE',headers:getHeaders()})
    .then(function(r){
      if(r.ok){
        var done=el.querySelector('.rc-ack-done');
        if(done)done.remove();
        var wrap=document.createElement('div');
        wrap.className='rc-ack-btns';
        var btn=document.createElement('button');
        btn.className='rc-ack-btn';
        btn.textContent='Acknowledge Finding';
        var tbtn=document.createElement('button');
        tbtn.className='rc-threat-btn';
        tbtn.textContent='Confirm Threat';
        var path=getPathFromFinding(el);
        (function(h,element,p){
          btn.onclick=function(){openModal(h,element,p,false)};
          tbtn.onclick=function(){openModal(h,element,p,true)};
        })(hash,el,path);
        wrap.appendChild(btn);
        wrap.appendChild(tbtn);
        el.appendChild(wrap);
      } else {
        alert('Undo failed \u2014 please try again.');
      }
    })
    .catch(function(){alert('Network error \u2014 please try again.')});
  }

  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

  // Bulk acknowledge
  function getUnackedFindings(){
    var findings=document.querySelectorAll('.finding');
    var unacked=[];
    var seen=new Set();
    for(var i=0;i<findings.length;i++){
      var el=findings[i];
      if(el.querySelector('.rc-ack-done'))continue;
      var hash=el.dataset.fhash;
      if(!hash||seen.has(hash))continue;
      seen.add(hash);
      unacked.push({hash:hash,el:el});
    }
    return unacked;
  }

  function openBulkModal(isThreat){
    var unacked=getUnackedFindings();
    if(!unacked.length){alert('All findings are already processed.');return;}
    var dlg=document.getElementById('rc-m-dialog');
    dlg.className=isThreat?'rc-modal threat':'rc-modal bulk';
    document.getElementById('rc-m-title').textContent=isThreat
      ?'BULK CONFIRM THREAT ('+unacked.length+' findings)'
      :'BULK ACKNOWLEDGE ('+unacked.length+' findings)';
    document.getElementById('rc-m-path').textContent='';
    document.getElementById('rc-m-desc').textContent=isThreat
      ?'Describe the confirmed threats. All '+unacked.length+' un-processed findings will be flagged as POSITIVE FINDING.'
      :'Enter one reason that applies to all '+unacked.length+' un-acknowledged findings. This will acknowledge them all at once.';
    document.getElementById('rc-m-save').textContent=isThreat
      ?'Confirm All Threats ('+unacked.length+')'
      :'Acknowledge All ('+unacked.length+')';
    document.getElementById('rc-m-save').onclick=function(){bulkSave(unacked,isThreat)};
    document.getElementById('rc-m-reason').placeholder=isThreat
      ?'e.g. All findings confirmed as Axios supply-chain compromise. Escalated to IR team.'
      :'e.g. None of these findings are related to the Axios supply-chain attack per MS Copilot analysis. Reviewed by mberry 2026-04-02.';
    document.getElementById('rc-m-reason').value='';
    document.getElementById('rc-m-err').textContent='';
    overlay.classList.add('open');
    setTimeout(function(){document.getElementById('rc-m-reason').focus()},50);
  }

  function bulkSave(unacked,isThreat){
    var reason=document.getElementById('rc-m-reason').value.trim();
    if(!reason){document.getElementById('rc-m-err').textContent='Reason is required.';return;}
    var saveBtn=document.getElementById('rc-m-save');
    saveBtn.disabled=true;
    var done=0,failed=0,total=unacked.length;
    document.getElementById('rc-m-err').textContent='';
    saveBtn.textContent='Saving... 0/'+total;

    var chain=Promise.resolve();
    unacked.forEach(function(item){
      chain=chain.then(function(){
        return fetch(B+'/api/submissions/'+SUB+'/acks',{
          method:'POST',
          headers:getHeaders(),
          body:JSON.stringify({finding_hash:item.hash,reason:reason,is_threat:!!isThreat})
        })
        .then(function(r){return r.json().then(function(b){return{status:r.status,body:b}})})
        .then(function(res){
          if(res.status===200||res.status===201||res.status===409){
            done++;
            markDone(item.el,reason,res.body.acknowledged_at||new Date().toISOString(),!!isThreat,item.hash);
          } else { failed++; }
          saveBtn.textContent='Saving... '+done+'/'+total;
        })
        .catch(function(){failed++});
      });
    });

    chain.then(function(){
      saveBtn.disabled=false;
      saveBtn.textContent=isThreat?'Confirm All Threats':'Acknowledge All';
      document.getElementById('rc-m-save').onclick=saveAck;
      if(failed===0){
        overlay.classList.remove('open');
      } else {
        document.getElementById('rc-m-err').textContent=failed+' of '+total+' failed. Try again for the remaining.';
      }
    });
  }

  // Wire up bulk buttons
  var bulkAckBtn=document.getElementById('rc-bulk-ack');
  if(bulkAckBtn)bulkAckBtn.onclick=function(){openBulkModal(false)};
  var bulkThreatBtn=document.getElementById('rc-bulk-threat');
  if(bulkThreatBtn)bulkThreatBtn.onclick=function(){openBulkModal(true)};


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
    var uniqueHashes=new Set();
    for(var i=0;i<findings.length;i++){
      var el=findings[i];
      var typeEl=el.querySelector('.f-type');
      var type=typeEl?typeEl.textContent.trim():'';
      var path=getPathFromFinding(el);
      var hash=await hashFinding(type,path);
      el.dataset.fhash=hash;
      uniqueHashes.add(hash);
      if(acksMap[hash]){
        markDone(el,acksMap[hash].reason,acksMap[hash].acknowledged_at,!!acksMap[hash].is_threat,hash);
      } else {
        var wrap=document.createElement('div');
        wrap.className='rc-ack-btns';
        var btn=document.createElement('button');
        btn.className='rc-ack-btn';
        btn.textContent='Acknowledge Finding';
        var tbtn=document.createElement('button');
        tbtn.className='rc-threat-btn';
        tbtn.textContent='Confirm Threat';
        (function(h,element,p){
          btn.onclick=function(){openModal(h,element,p,false)};
          tbtn.onclick=function(){openModal(h,element,p,true)};
        })(hash,el,path||type);
        wrap.appendChild(btn);
        wrap.appendChild(tbtn);
        el.appendChild(wrap);
      }
    }
    // Correct findings_count if HTML has duplicate finding divs
    if(uniqueHashes.size!==findings.length){
      fetch(B+'/api/submissions/'+SUB+'/findings-count',{
        method:'PUT',
        headers:getHeaders(),
        body:JSON.stringify({count:uniqueHashes.size})
      }).catch(function(){});
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

export async function handleUserSubmissions(request, env) {
  const url      = new URL(request.url)
  const username = (url.searchParams.get('username') || '').trim()

  if (!username) return json({ error: 'Missing parameters' }, 400)

  const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1',  10) || 1)
  const limit  = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 1))
  const offset = (page - 1) * limit

  try {
    const countRow = await env.DB.prepare(
      'SELECT COUNT(*) AS total FROM submissions WHERE LOWER(username) = LOWER(?)'
    ).bind(username).first()
    const total = countRow?.total ?? 0

    if (!total) return json({ error: 'Not found' }, 404)

    const rows = await env.DB.prepare(`
      SELECT s.id, s.hostname, s.username, s.submitted_at, s.verdict, s.duration,
             s.projects_scanned, s.findings_count,
             CASE WHEN s.submitted_at = latest.max_at THEN 1 ELSE 0 END AS is_latest,
             COALESCE(ac.ack_count, 0) AS ack_count,
             COALESCE(tc.threat_count, 0) AS threat_count,
             CASE WHEN COALESCE(tc.threat_count, 0) > 0 THEN 1 ELSE 0 END AS positive,
             CASE WHEN COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0
                       AND COALESCE(ac.ack_count, 0) >= s.findings_count
                  THEN 1 ELSE 0 END AS reviewed
      FROM submissions s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
      WHERE LOWER(s.username) = LOWER(?)
      ORDER BY s.submitted_at DESC
      LIMIT ? OFFSET ?
    `).bind(username, limit, offset).all()

    return json({ total, page, limit, submissions: rows.results })
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
