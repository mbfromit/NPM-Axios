const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RatCatcher - Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f0f0f;color:#e0e0e0;font-family:'Courier New',monospace;min-height:100vh}
#choice,#login,#ulogin{display:none;align-items:center;justify-content:center;min-height:100vh}
#choice{display:flex}
.lbox{background:#1a1a1a;border:1px solid #2a2a2a;padding:40px;width:360px}
.lbox h1{color:#00ff41;font-size:1.5rem;text-align:center;margin-bottom:6px;letter-spacing:2px}
.lbox .sub{color:#555;text-align:center;font-size:0.78rem;margin-bottom:28px;text-transform:uppercase;letter-spacing:1px}
.lbox .uhelp{color:#666;font-size:0.75rem;margin-bottom:20px;line-height:1.7}
.lbox .uhelp code{color:#00ff41;background:#0a0a0a;padding:1px 5px}
input[type=password],input[type=text]{display:block;width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;color:#e0e0e0;font-family:monospace;font-size:0.9rem;margin-bottom:10px}
input[type=password]:focus,input[type=text]:focus{outline:none;border-color:#00ff41}
.btn{display:block;width:100%;padding:10px;background:#00ff41;color:#0f0f0f;border:none;font-family:monospace;font-size:0.9rem;font-weight:bold;cursor:pointer;text-transform:uppercase;letter-spacing:1px}
.btn:hover{background:#00cc33}
.btn-out{display:block;width:100%;padding:10px;background:none;color:#00ff41;border:1px solid #00ff41;font-family:monospace;font-size:0.9rem;font-weight:bold;cursor:pointer;text-transform:uppercase;letter-spacing:1px;margin-top:10px}
.btn-out:hover{background:rgba(0,255,65,0.08)}
.div-or{text-align:center;color:#333;font-size:0.75rem;margin:12px 0}
.lerr{color:#ff4444;font-size:0.8rem;margin-top:8px;min-height:18px}
.back-link{background:none;border:none;color:#444;font-family:monospace;font-size:0.75rem;cursor:pointer;padding:0;margin-top:14px;display:block;text-align:center;width:100%}
.back-link:hover{color:#777}
#dash,#udash{display:none;padding:24px;max-width:1200px;margin:0 auto}
.hdr{display:flex;align-items:baseline;gap:14px;margin-bottom:24px;border-bottom:1px solid #1a1a1a;padding-bottom:14px}
.hdr h1{color:#00ff41;font-size:1.1rem;letter-spacing:2px}
.hdr .badge{color:#444;font-size:0.78rem}
.stats{display:flex;gap:12px;margin-bottom:28px;flex-wrap:wrap}
.stat{flex:1;min-width:120px;background:#1a1a1a;border:1px solid #222;padding:12px 8px;text-align:center;cursor:pointer;transition:border-color 0.2s}
.stat:hover{border-color:#444}
.stat.selected{border-color:#00ff41}
.stat .lbl{color:#555;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.stat .val{font-size:1.8rem;font-weight:bold;color:#e0e0e0}
.stat.clean .val{color:#00ff41}
.stat.comp .val{color:#ff4444}
.stat.pos .val{color:#f85149}
.stat.rvw .val{color:#3fb950}
.stat.nrvw .val{color:#f0883e}
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
.gear+.gear{margin-left:0}
.dbtn{background:none;border:1px solid #4a1a1a;color:#ff4444;padding:3px 8px;cursor:pointer;font-family:monospace;font-size:0.72rem;display:none}
.dbtn:hover{background:#4a1a1a;border-color:#ff4444}
.admin-on .dbtn{display:inline-block}
.xbtn{background:none;border:1px solid #2a2a2a;color:#555;padding:4px 10px;cursor:pointer;font-size:0.78rem;font-family:monospace;display:none}
.xbtn:hover{border-color:#00ff41;color:#00ff41}
.admin-on .xbtn{display:inline-block}
.search{display:flex;gap:10px;margin-bottom:16px;align-items:center}
.search input{background:#0a0a0a;border:1px solid #333;color:#e0e0e0;font-family:monospace;font-size:0.82rem;padding:6px 12px;width:260px}
.search input:focus{outline:none;border-color:#00ff41}
.search .clr{background:none;border:1px solid #2a2a2a;color:#555;padding:4px 10px;cursor:pointer;font-family:monospace;font-size:0.78rem}
.search .clr:hover{border-color:#555;color:#999}
.latest{color:#00ff41;font-size:0.68rem;font-weight:bold;margin-left:6px;letter-spacing:1px}
.reviewed{color:#3fb950;font-size:0.68rem;font-weight:bold;margin-left:6px;letter-spacing:1px}
.positive{color:#f85149;font-size:0.68rem;font-weight:bold;margin-left:6px;letter-spacing:1px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
</style>
</head>
<body>

<!-- Choice screen -->
<div id="choice">
  <div class="lbox">
    <h1>RATCATCHER</h1>
    <p class="sub">Endpoint Security Scanner</p>
    <button class="btn" id="goAdmin">&#9881; Admin Dashboard</button>
    <div class="div-or">&mdash; OR &mdash;</div>
    <button class="btn-out" id="goUser">&#128196; View My Scans</button>
  </div>
</div>

<!-- Admin login -->
<div id="login">
  <div class="lbox">
    <h1>RATCATCHER</h1>
    <p class="sub">Admin Dashboard</p>
    <form id="lf">
      <input type="password" id="pw" placeholder="Admin password" autocomplete="current-password">
      <button type="submit" class="btn">Sign In</button>
      <div class="lerr" id="lerr"></div>
    </form>
    <button class="back-link" id="backChoice">&#8592; Back</button>
  </div>
</div>

<!-- User login -->
<div id="ulogin">
  <div class="lbox">
    <h1>RATCATCHER</h1>
    <p class="sub">View My Scans</p>
    <p class="uhelp">Enter the <strong style="color:#ccc">username</strong> you were logged in as when your RatCatcher scan was run.<br><br>Not sure? Check the top of your scan output, or open Command Prompt and type <code>whoami</code>.</p>
    <form id="ulf">
      <input type="text" id="uname" placeholder="Username (e.g. jsmith)" autocomplete="username">
      <button type="submit" class="btn">View My Scans</button>
      <div class="lerr" id="ulerr"></div>
    </form>
    <button class="back-link" id="backChoiceU">&#8592; Back</button>
  </div>
</div>

<!-- Admin dashboard -->
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
    <div class="stat pos" id="f-pos"><div class="lbl">Positive Findings</div><div class="val" id="s-pos">-</div></div>
    <div class="stat rvw" id="f-reviewed"><div class="lbl">Reviewed</div><div class="val" id="s-reviewed">-</div></div>
    <div class="stat nrvw" id="f-notrev"><div class="lbl">Not Reviewed</div><div class="val" id="s-notrev">-</div></div>
  </div>
  <div class="search">
    <input type="text" id="srch" placeholder="Search hostname or username...">
    <button class="clr" id="srchclr">Clear</button>
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

<!-- User dashboard -->
<div id="udash">
  <div class="hdr">
    <h1>RATCATCHER</h1>
    <span class="badge" id="ubadge">My Scans</span>
    <button class="gear" id="ulogout">&#9211; Sign Out</button>
  </div>
  <div class="tblw">
    <table>
      <thead><tr>
        <th>Submitted</th><th>Hostname</th><th>Duration</th><th>Verdict</th><th>Reports</th>
      </tr></thead>
      <tbody id="utb"></tbody>
    </table>
  </div>
  <div class="pager">
    <button class="pbtn" id="upp" disabled>&larr; Prev</button>
    <span class="pginfo" id="upgi"></span>
    <button class="pbtn" id="upn" disabled>Next &rarr;</button>
  </div>
</div>

<script>
const B='/ratcatcher',L=50;
var pw='';
let pg=1,refreshTimer=null,vfilter='',rfilter='',pfilter='',srchQ='';
let uPg=1,uUser='',uHost='';

function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function fmtDur(d){if(!d)return'\u2014';const s=parseFloat(d);if(isNaN(s))return d;const m=s/60;return m<1?'<1 min':Math.round(m)+' min'}
function show(id,mode){document.getElementById(id).style.display=mode||'block'}
function hide(ids){ids.forEach(function(id){document.getElementById(id).style.display='none'})}

// ── Choice screen ──
function showChoice(){
  hide(['login','ulogin','dash','udash']);
  show('choice','flex');
}
document.getElementById('goAdmin').addEventListener('click',function(){
  hide(['choice']);show('login','flex');
  setTimeout(function(){document.getElementById('pw').focus()},50);
});
document.getElementById('goUser').addEventListener('click',function(){
  hide(['choice']);show('ulogin','flex');
  setTimeout(function(){document.getElementById('uname').focus()},50);
});
document.getElementById('backChoice').addEventListener('click',function(){hide(['login']);showChoice()});
document.getElementById('backChoiceU').addEventListener('click',function(){hide(['ulogin']);showChoice()});

// ── Admin ──
async function api(p){return fetch(B+p,{headers:{'X-Admin-Password':pw}})}
async function chkAuth(){
  if(!pw)return false;
  const r=await api('/api/stats');
  if(r.ok)return true;
  pw='';sessionStorage.removeItem('rcpw');return false;
}
async function loadStats(){
  try{
    const r=await api('/api/stats'),d=await r.json();
    document.getElementById('s-total').textContent=(d.total??0).toLocaleString();
    document.getElementById('s-clean').textContent=(d.clean??0).toLocaleString();
    document.getElementById('s-comp').textContent=(d.compromised??0).toLocaleString();
    document.getElementById('s-pos').textContent=(d.positive??0).toLocaleString();
    document.getElementById('s-reviewed').textContent=(d.reviewed??0).toLocaleString();
    document.getElementById('s-notrev').textContent=(d.not_reviewed??0).toLocaleString();
  }catch(e){console.error('loadStats',e)}
}
async function loadRows(){
  const r=await api('/api/submissions?page='+pg+'&limit='+L+(vfilter?'&verdict='+vfilter:'')+(pfilter?'&positive=1':'')+(rfilter!==''?'&reviewed='+rfilter:'')+(srchQ?'&search='+encodeURIComponent(srchQ):'')),d=await r.json();
  const tb=document.getElementById('tb');
  tb.innerHTML='';
  if(!d.submissions||!d.submissions.length){
    tb.innerHTML='<tr><td colspan="6" class="empty">No submissions yet.</td></tr>';
  } else {
    d.submissions.forEach(function(s){
      const tr=document.createElement('tr');
      tr.className=s.verdict==='COMPROMISED'?'comp':'clean';
      const dt=new Date(s.submitted_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'});
      const ltag=s.is_latest?'<span class="latest">LATEST</span>':'';
      tr.innerHTML='<td>'+esc(dt)+'</td><td>'+esc(s.hostname)+ltag+'</td><td>'+esc(s.username)+'</td>'
        +'<td>'+esc(fmtDur(s.duration))+'</td>'
        +'<td class="vrd">'+(s.verdict==='COMPROMISED'?'[!] COMPROMISED':'[+] CLEAN')
        +(s.positive?'<span class="positive"> &#9888; POSITIVE FINDING</span>':s.reviewed?'<span class="reviewed"> &#10003; REVIEWED</span>':'')+'</td>'
        +'<td>'
        +'<button class="vbtn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;brief&#39;)">Exec Brief</button> '
        +'<button class="vbtn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;full&#39;)">Technical Report</button> '
        +'<button class="dbtn" onclick="del(&#39;'+esc(s.id)+'&#39;,&#39;'+esc(s.hostname)+'&#39;,&#39;'+esc(s.username)+'&#39;)">Delete</button>'
        +'</td>';
      tb.appendChild(tr);
    });
  }
  const tp=Math.max(1,Math.ceil(d.total/L));
  document.getElementById('pgi').textContent='Page '+pg+' of '+tp;
  document.getElementById('pp').disabled=pg<=1;
  document.getElementById('pn').disabled=pg>=tp;
}
async function vw(id,type){
  const r=await api('/api/report/'+id+'/'+(type||'brief'));
  if(!r.ok){alert('Failed to load report ('+r.status+')');return;}
  const blob=await r.blob();
  window.open(URL.createObjectURL(blob),'_blank');
}
async function refresh(){try{await Promise.all([loadStats(),loadRows()])}catch(e){}}
async function showDash(){
  hide(['choice','login','ulogin','udash']);
  show('dash','block');
  await Promise.all([loadStats(),loadRows()]);
  if(refreshTimer)clearInterval(refreshTimer);
  refreshTimer=setInterval(refresh,30000);
}
function logout(){
  if(refreshTimer)clearInterval(refreshTimer);
  pw='';sessionStorage.removeItem('rcpw');
  document.getElementById('dash').classList.remove('admin-on');
  document.getElementById('admtog').classList.remove('active');
  document.getElementById('pw').value='';
  document.getElementById('lerr').textContent='';
  showChoice();
}
document.getElementById('lf').addEventListener('submit',async function(e){
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
function setFilter(v,rv,pf){
  vfilter=v;rfilter=rv??'';pfilter=pf??'';pg=1;
  document.querySelectorAll('.stat').forEach(function(el){el.classList.remove('selected')});
  if(pf)document.getElementById('f-pos').classList.add('selected');
  else if(rv==='1')document.getElementById('f-reviewed').classList.add('selected');
  else if(rv==='0')document.getElementById('f-notrev').classList.add('selected');
  else document.getElementById(v==='CLEAN'?'f-clean':v==='COMPROMISED'?'f-comp':'f-all').classList.add('selected');
  loadRows();
}
document.getElementById('f-all').addEventListener('click',function(){setFilter('','','')});
document.getElementById('f-clean').addEventListener('click',function(){setFilter('CLEAN','','')});
document.getElementById('f-comp').addEventListener('click',function(){setFilter('COMPROMISED','','')});
document.getElementById('f-pos').addEventListener('click',function(){setFilter('','','1')});
document.getElementById('f-reviewed').addEventListener('click',function(){setFilter('','1','')});
document.getElementById('f-notrev').addEventListener('click',function(){setFilter('COMPROMISED','0','')});
let srchTimer=null;
document.getElementById('srch').addEventListener('input',function(){
  clearTimeout(srchTimer);
  srchTimer=setTimeout(function(){srchQ=document.getElementById('srch').value.trim();pg=1;loadRows()},300);
});
document.getElementById('srchclr').addEventListener('click',function(){
  document.getElementById('srch').value='';srchQ='';pg=1;loadRows();
});
document.getElementById('logout').addEventListener('click',logout);
document.getElementById('csvbtn').addEventListener('click',async function(){
  const r=await api('/api/export');
  if(!r.ok){alert('Export failed ('+r.status+')');return;}
  const blob=await r.blob();
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download='ratcatcher-export.csv';a.click();
});
document.getElementById('pp').addEventListener('click',function(){pg--;loadRows()});
document.getElementById('pn').addEventListener('click',function(){pg++;loadRows()});

// ── User ──
async function checkUserAuth(username){
  const r=await fetch(B+'/api/user-submissions?username='+encodeURIComponent(username));
  return r.ok;
}
async function loadUserRows(){
  const r=await fetch(B+'/api/user-submissions?username='+encodeURIComponent(uUser)+'&page='+uPg+'&limit='+L);
  const d=await r.json();
  const tb=document.getElementById('utb');
  tb.innerHTML='';
  if(!d.submissions||!d.submissions.length){
    tb.innerHTML='<tr><td colspan="5" class="empty">No scans found.</td></tr>';
  } else {
    d.submissions.forEach(function(s){
      const tr=document.createElement('tr');
      tr.className=s.verdict==='COMPROMISED'?'comp':'clean';
      const dt=new Date(s.submitted_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'});
      const ltag=s.is_latest?'<span class="latest">LATEST</span>':'';
      tr.innerHTML='<td>'+esc(dt)+'</td><td>'+esc(s.hostname)+ltag+'</td>'
        +'<td>'+esc(fmtDur(s.duration))+'</td>'
        +'<td class="vrd">'+(s.verdict==='COMPROMISED'?'[!] COMPROMISED':'[+] CLEAN')
        +(s.positive?'<span class="positive"> &#9888; POSITIVE FINDING</span>':s.reviewed?'<span class="reviewed"> &#10003; REVIEWED</span>':'')+'</td>'
        +'<td>'
        +'<button class="vbtn" onclick="vwUser(&#39;'+esc(s.id)+'&#39;,&#39;brief&#39;)">Exec Brief</button> '
        +'<button class="vbtn" onclick="vwUser(&#39;'+esc(s.id)+'&#39;,&#39;full&#39;)">Technical Report</button>'
        +'</td>';
      tb.appendChild(tr);
    });
  }
  const tp=Math.max(1,Math.ceil((d.total||0)/L));
  document.getElementById('upgi').textContent='Page '+uPg+' of '+tp;
  document.getElementById('upp').disabled=uPg<=1;
  document.getElementById('upn').disabled=uPg>=tp;
}
async function vwUser(id,type){
  const r=await fetch(B+'/api/user-report/'+id+'/'+(type||'brief')+'?username='+encodeURIComponent(uUser));
  if(!r.ok){alert('Failed to load report ('+r.status+')');return;}
  const blob=await r.blob();
  window.open(URL.createObjectURL(blob),'_blank');
}
async function showUserDash(username){
  uUser=username;uPg=1;
  document.getElementById('ubadge').textContent=username+'\'s Scans';
  hide(['choice','login','ulogin','dash']);
  show('udash','block');
  await loadUserRows();
}
function userLogout(){
  uUser='';uHost='';
  sessionStorage.removeItem('rcuser');
  showChoice();
}
document.getElementById('ulf').addEventListener('submit',async function(e){
  e.preventDefault();
  const username=document.getElementById('uname').value.trim();
  if(!username){document.getElementById('ulerr').textContent='Username is required.';return;}
  document.getElementById('ulerr').textContent='Checking\u2026';
  const ok=await checkUserAuth(username);
  if(!ok){document.getElementById('ulerr').textContent='No scans found for that username.';return;}
  document.getElementById('ulerr').textContent='';
  sessionStorage.setItem('rcuser',JSON.stringify({username:username}));
  await showUserDash(username);
});
document.getElementById('ulogout').addEventListener('click',userLogout);
document.getElementById('upp').addEventListener('click',function(){uPg--;loadUserRows()});
document.getElementById('upn').addEventListener('click',function(){uPg++;loadUserRows()});

// ── Session restore ──
(async function(){
  var savedPw=sessionStorage.getItem('rcpw');
  var savedUser=sessionStorage.getItem('rcuser');
  if(savedPw){
    pw=savedPw;
    var ok=await chkAuth();
    if(ok){await showDash();return;}
    pw='';
  }
  if(savedUser){
    try{
      var u=JSON.parse(savedUser);
      var uok=await checkUserAuth(u.username);
      if(uok){await showUserDash(u.username);return;}
    }catch(ex){}
    sessionStorage.removeItem('rcuser');
  }
  showChoice();
})();
</script>
</body>
</html>`

export async function handleDashboard() {
  return new Response(HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
}
