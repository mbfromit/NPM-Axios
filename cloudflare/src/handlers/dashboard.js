const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RatCatcher - Manager Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f0f0f;color:#e0e0e0;font-family:'Courier New',monospace;min-height:100vh}
#login{display:flex;align-items:center;justify-content:center;min-height:100vh}
.lbox{background:#1a1a1a;border:1px solid #2a2a2a;padding:40px;width:360px}
.lbox h1{color:#00ff41;font-size:1.5rem;text-align:center;margin-bottom:6px;letter-spacing:2px}
.lbox .sub{color:#555;text-align:center;font-size:0.78rem;margin-bottom:28px;text-transform:uppercase;letter-spacing:1px}
input[type=password]{display:block;width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;color:#e0e0e0;font-family:monospace;font-size:0.9rem;margin-bottom:10px}
input[type=password]:focus{outline:none;border-color:#00ff41}
.btn{display:block;width:100%;padding:10px;background:#00ff41;color:#0f0f0f;border:none;font-family:monospace;font-size:0.9rem;font-weight:bold;cursor:pointer;text-transform:uppercase;letter-spacing:1px}
.btn:hover{background:#00cc33}
.lerr{color:#ff4444;font-size:0.8rem;margin-top:8px;min-height:18px}
#dash{display:none;padding:24px;max-width:1200px;margin:0 auto}
.hdr{display:flex;align-items:baseline;gap:14px;margin-bottom:24px;border-bottom:1px solid #1a1a1a;padding-bottom:14px}
.hdr h1{color:#00ff41;font-size:1.1rem;letter-spacing:2px}
.hdr .badge{color:#444;font-size:0.78rem}
.stats{display:flex;gap:12px;margin-bottom:28px}
.stat{flex:1;background:#1a1a1a;border:1px solid #222;padding:18px;text-align:center;cursor:pointer;transition:border-color 0.2s}
.stat:hover{border-color:#444}
.stat.selected{border-color:#00ff41}
.stat .lbl{color:#555;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.stat .val{font-size:2.2rem;font-weight:bold;color:#e0e0e0}
.stat.clean .val{color:#00ff41}
.stat.comp .val{color:#ff4444}
.tblw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:0.82rem}
th{background:#111;color:#444;text-align:left;padding:8px 14px;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1e1e1e}
td{padding:9px 14px;border-bottom:1px solid #141414;white-space:nowrap}
tr.comp td{background:rgba(220,38,38,0.07)}
tr.comp .vrd{color:#ff4444;font-weight:bold}
tr.clean .vrd{color:#00ff41}
tr:hover td{background:#1a1a1a}
.vbtn{background:none;border:1px solid #2a2a2a;color:#777;padding:3px 10px;cursor:pointer;font-family:monospace;font-size:0.78rem}
.vbtn:hover{border-color:#00ff41;color:#00ff41}
.pager{display:flex;justify-content:flex-end;align-items:center;gap:12px;margin-top:16px}
.pbtn{background:#1a1a1a;border:1px solid #2a2a2a;color:#ccc;padding:5px 14px;cursor:pointer;font-family:monospace;font-size:0.8rem}
.pbtn:disabled{opacity:0.3;cursor:default}
.pginfo{color:#444;font-size:0.8rem}
.empty{color:#444;text-align:center;padding:40px 0;font-size:0.85rem}
.gear{background:none;border:1px solid #2a2a2a;color:#555;padding:4px 10px;cursor:pointer;font-size:0.85rem;font-family:monospace;margin-left:auto}
.gear:hover{border-color:#555;color:#999}
.gear.active{border-color:#ff4444;color:#ff4444}
.dbtn{background:none;border:1px solid #4a1a1a;color:#ff4444;padding:3px 8px;cursor:pointer;font-family:monospace;font-size:0.72rem;display:none}
.dbtn:hover{background:#4a1a1a;border-color:#ff4444}
.admin-on .dbtn{display:inline-block}
.xbtn{background:none;border:1px solid #2a2a2a;color:#555;padding:4px 10px;cursor:pointer;font-size:0.78rem;font-family:monospace;display:none}
.xbtn:hover{border-color:#00ff41;color:#00ff41}
.admin-on .xbtn{display:inline-block}
</style>
</head>
<body>
<div id="login">
  <div class="lbox">
    <h1>RATCATCHER</h1>
    <p class="sub">Manager Dashboard</p>
    <form id="lf">
      <input type="password" id="pw" placeholder="Admin password" autocomplete="current-password">
      <button type="submit" class="btn">Sign In</button>
      <div class="lerr" id="lerr"></div>
    </form>
  </div>
</div>
<div id="dash">
  <div class="hdr">
    <h1>RATCATCHER</h1>
    <span class="badge">Manager Dashboard</span>
    <button class="gear" id="admtog" title="Admin Tools">&#9881; Admin</button>
    <button class="gear" id="logout" title="Sign out">&#9211; Logout</button>
  </div>
  <div class="stats">
    <div class="stat selected" id="f-all"><div class="lbl">Total Scans</div><div class="val" id="s-total">-</div></div>
    <div class="stat clean" id="f-clean"><div class="lbl">Clean</div><div class="val" id="s-clean">-</div></div>
    <div class="stat comp" id="f-comp"><div class="lbl">Compromised</div><div class="val" id="s-comp">-</div></div>
  </div>
  <div class="tblw">
    <table>
      <thead><tr>
        <th>Submitted</th><th>Hostname</th><th>User</th>
        <th>Duration</th><th>Verdict</th><th>Actions</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="pager">
    <button class="xbtn" id="csvbtn">&#8615; Export CSV</button>
    <button class="pbtn" id="pp" disabled>&larr; Prev</button>
    <span class="pginfo" id="pgi"></span>
    <button class="pbtn" id="pn" disabled>Next &rarr;</button>
  </div>
</div>
<script>
const B='/ratcatcher',L=50;let pw='',pg=1,refreshTimer=null,vfilter='';
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function fmtDur(d){if(!d)return'—';const s=parseFloat(d);if(isNaN(s))return d;const m=s/60;return m<1?'<1 min':Math.round(m)+' min'}
async function api(p){return fetch(B+p,{headers:{'X-Admin-Password':pw}})}
async function chkAuth(){
  if(!pw)return false;
  const r=await api('/api/stats');
  if(r.ok)return true;
  pw='';sessionStorage.removeItem('rcpw');return false;
}
async function loadStats(){
  const r=await api('/api/stats'),d=await r.json();
  document.getElementById('s-total').textContent=d.total.toLocaleString();
  document.getElementById('s-clean').textContent=d.clean.toLocaleString();
  document.getElementById('s-comp').textContent=d.compromised.toLocaleString();
}
async function loadRows(){
  const r=await api('/api/submissions?page='+pg+'&limit='+L+(vfilter?'&verdict='+vfilter:'')),d=await r.json();
  const tb=document.getElementById('tb');
  tb.innerHTML='';
  if(!d.submissions||!d.submissions.length){
    tb.innerHTML='<tr><td colspan="6" class="empty">No submissions yet.</td></tr>';
  } else {
    d.submissions.forEach(s=>{
      const tr=document.createElement('tr');
      tr.className=s.verdict==='COMPROMISED'?'comp':'clean';
      const dt=new Date(s.submitted_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'});
      tr.innerHTML='<td>'+esc(dt)+'</td><td>'+esc(s.hostname)+'</td><td>'+esc(s.username)+'</td>'
        +'<td>'+esc(fmtDur(s.duration))+'</td>'
        +'<td class="vrd">'+(s.verdict==='COMPROMISED'?'[!] COMPROMISED':'[+] CLEAN')+'</td>'
        +'<td><button class="vbtn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;brief&#39;)">Exec Brief</button> <button class="vbtn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;full&#39;)">Technical Report</button>'
        +' <button class="dbtn" onclick="del(&#39;'+esc(s.id)+'&#39;,&#39;'+esc(s.hostname)+'&#39;,&#39;'+esc(s.username)+'&#39;)">Delete</button></td>';
      tb.appendChild(tr);
    });
  }
  const tp=Math.max(1,Math.ceil(d.total/L));
  document.getElementById('pgi').textContent='Page '+pg+' of '+tp;
  document.getElementById('pp').disabled=pg<=1;
  document.getElementById('pn').disabled=pg>=tp;
}
async function vw(id,type='brief'){
  const r=await api('/api/report/'+id+'/'+type);
  if(!r.ok){alert('Failed to load report ('+r.status+')');return;}
  const blob=await r.blob();
  window.open(URL.createObjectURL(blob),'_blank');
}
async function refresh(){try{await Promise.all([loadStats(),loadRows()])}catch(e){}}
async function showDash(){
  document.getElementById('login').style.display='none';
  document.getElementById('dash').style.display='block';
  await Promise.all([loadStats(),loadRows()]);
  if(refreshTimer)clearInterval(refreshTimer);
  refreshTimer=setInterval(refresh,30000);
}
function logout(){
  if(refreshTimer)clearInterval(refreshTimer);
  pw='';sessionStorage.removeItem('rcpw');
  document.getElementById('dash').style.display='none';
  document.getElementById('dash').classList.remove('admin-on');
  document.getElementById('admtog').classList.remove('active');
  document.getElementById('login').style.display='flex';
  document.getElementById('pw').value='';
  document.getElementById('lerr').textContent='';
}
document.getElementById('lf').addEventListener('submit',async e=>{
  e.preventDefault();
  pw=document.getElementById('pw').value.trim();
  const r=await api('/api/stats');
  if(r.status===401){document.getElementById('lerr').textContent='Incorrect password';pw='';return;}
  document.getElementById('lerr').textContent='';
  sessionStorage.setItem('rcpw',pw);
  await showDash();
});
async function del(id,host,user){
  if(!confirm('Delete submission from '+host+' ('+user+')?\\n\\nThis will permanently remove the scan record and both reports.'))return;
  const r=await fetch(B+'/api/submissions/'+id,{method:'DELETE',headers:{'X-Admin-Password':pw}});
  if(!r.ok){alert('Delete failed ('+r.status+')');return;}
  await Promise.all([loadStats(),loadRows()]);
}
document.getElementById('admtog').addEventListener('click',function(){
  this.classList.toggle('active');
  document.getElementById('dash').classList.toggle('admin-on');
});
function setFilter(v){
  vfilter=v;pg=1;
  document.querySelectorAll('.stat').forEach(el=>el.classList.remove('selected'));
  document.getElementById(v==='CLEAN'?'f-clean':v==='COMPROMISED'?'f-comp':'f-all').classList.add('selected');
  loadRows();
}
document.getElementById('f-all').addEventListener('click',()=>setFilter(''));
document.getElementById('f-clean').addEventListener('click',()=>setFilter('CLEAN'));
document.getElementById('f-comp').addEventListener('click',()=>setFilter('COMPROMISED'));
document.getElementById('logout').addEventListener('click',logout);
document.getElementById('csvbtn').addEventListener('click',async()=>{
  const r=await api('/api/export');
  if(!r.ok){alert('Export failed ('+r.status+')');return;}
  const blob=await r.blob();
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download='ratcatcher-export.csv';a.click();
});
document.getElementById('pp').addEventListener('click',()=>{pg--;loadRows()});
document.getElementById('pn').addEventListener('click',()=>{pg++;loadRows()});
pw=sessionStorage.getItem('rcpw')||'';
chkAuth().then(ok=>{if(ok)showDash()});
</script>
</body>
</html>`

export async function handleDashboard() {
  return new Response(HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
}
