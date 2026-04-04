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
#dash{display:none;padding:24px;max-width:1600px;margin:0 auto}
.hdr{display:flex;align-items:baseline;gap:14px;margin-bottom:24px;border-bottom:1px solid #1a1a1a;padding-bottom:14px}
.hdr h1{color:#00ff41;font-size:1.1rem;letter-spacing:2px}
.hdr .badge{color:#444;font-size:0.78rem}
.stats{display:flex;gap:12px;margin-bottom:28px}
.stat{flex:1;min-width:120px;background:#1a1a1a;border:1px solid #222;padding:12px 8px;text-align:center;cursor:pointer;transition:border-color 0.2s}
.stat:hover{border-color:#444}
.stat.selected{border-color:#00ff41}
.stat .lbl{color:#555;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.stat .val{font-size:1.8rem;font-weight:bold;color:#e0e0e0}
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
.search{display:flex;gap:10px;margin-bottom:16px;align-items:center}
.search input{background:#0a0a0a;border:1px solid #333;color:#e0e0e0;font-family:monospace;font-size:0.82rem;padding:6px 12px;width:260px}
.search input:focus{outline:none;border-color:#00ff41}
.search .clr{background:none;border:1px solid #2a2a2a;color:#555;padding:4px 10px;cursor:pointer;font-family:monospace;font-size:0.78rem}
.search .clr:hover{border-color:#555;color:#999}
.latest{color:#00ff41;font-size:0.68rem;font-weight:bold;margin-left:6px;letter-spacing:1px}
.reviewed{color:#3fb950;font-size:0.68rem;font-weight:bold;margin-left:6px;letter-spacing:1px}
.positive{color:#f85149;font-size:0.68rem;font-weight:bold;margin-left:6px;letter-spacing:1px;animation:pulse 2s infinite}
tr.ai-fp .vrd{color:#e8a838;font-weight:bold}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
.stat.pos .val{color:#f85149}
.stat.rvw .val{color:#3fb950}
.stat.nrvw .val{color:#f0883e}
.stats{flex-wrap:wrap}
.aibtn{background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:3px 10px;cursor:pointer;font-family:monospace;font-size:0.72rem}
.aibtn:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.aibtn:disabled{opacity:0.5;cursor:default}
.aibtn.running{border-color:#e8a838;color:#e8a838;animation:pulse 1.5s infinite}
.ai-done{color:#3fb950;font-size:0.68rem;font-weight:bold;font-family:monospace}
.cert-btn{background:none;border:1px solid #5f2a2a;color:#f85149;padding:3px 10px;cursor:pointer;font-family:monospace;font-size:0.72rem}
.cert-btn:hover{border-color:#f85149;background:rgba(248,81,73,.08)}
.cert-done{font-size:0.68rem;font-weight:bold;font-family:monospace;color:#3fb950}
.await-review{color:#e8a838;font-size:0.68rem;font-weight:bold;font-family:monospace}
.cert-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:10002;align-items:center;justify-content:center}
.cert-overlay.open{display:flex}
.cert-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:28px;width:440px;max-width:92vw}
.cert-modal h3{color:#f85149;font-family:monospace;font-size:13px;letter-spacing:2px;margin-bottom:16px}
.cert-modal p{color:#8b949e;font-size:12px;font-family:monospace;margin-bottom:14px;line-height:1.5}
.cert-modal input{width:100%;background:#06090f;border:1px solid #21303f;color:#c9d1d9;font-family:monospace;font-size:12px;padding:10px;border-radius:4px}
.cert-modal input:focus{outline:none;border-color:#f85149}
.cert-modal .cert-err{color:#f85149;font-size:11px;min-height:16px;margin-top:6px;font-family:monospace}
.cert-modal .cert-btns{display:flex;gap:10px;margin-top:14px;justify-content:flex-end}
.cert-modal .cert-btns button{padding:6px 18px;font-family:monospace;font-size:12px;border-radius:3px;cursor:pointer}
.cert-cancel{background:none;border:1px solid #2a2a2a;color:#6e7681}
.cert-cancel:hover{border-color:#555;color:#ccc}
.cert-save{background:#da3633;border:1px solid #f85149;color:#fff;font-weight:bold}
.cert-save:hover{background:#f85149}
.ai-all-btn{background:none;border:1px solid #2a3f5f;color:#58a6ff;padding:4px 10px;cursor:pointer;font-size:0.78rem;font-family:monospace}
.ai-all-btn:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.ai-all-btn:disabled{opacity:0.5;cursor:default}
.ai-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:10000;align-items:center;justify-content:center}
.ai-overlay.open{display:flex}
.ai-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:28px;width:600px;max-width:92vw;max-height:80vh;overflow-y:auto}
.ai-modal h3{color:#58a6ff;font-family:monospace;font-size:13px;letter-spacing:2px;margin-bottom:16px}
.ai-checklist{margin-bottom:12px}
.ai-check-item{font-size:12px;font-family:monospace;padding:4px 0;color:#8b949e}
.ai-check-item.done{color:#3fb950}
.ai-check-item.active{color:#e8a838}
.ai-check-item.err{color:#f85149}
.ai-check-item .ai-chk{display:inline-block;width:18px}
.ai-modal .ai-status{color:#e8a838;font-size:12px;font-family:monospace;margin-bottom:16px;min-height:18px}
.ai-modal .ai-status.done{color:#3fb950}
.ai-modal .ai-status.err{color:#f85149}
.ai-spinner{display:inline-block;width:12px;height:12px;border:2px solid #e8a838;border-top-color:transparent;border-radius:50%;animation:spin .8s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.ai-findings{display:flex;flex-direction:column;gap:10px}
.ai-finding{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:12px 14px}
.ai-finding .ai-f-hdr{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.ai-finding .ai-f-cat{color:#8b949e;font-size:11px;font-family:monospace;text-transform:uppercase;letter-spacing:1px}
.ai-finding .ai-f-verdict{font-size:11px;font-family:monospace;font-weight:bold;padding:2px 8px;border-radius:3px}
.ai-f-verdict.confirmed,.ai-f-verdict.likely{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3)}
.ai-f-verdict.unlikely,.ai-f-verdict.falsepositive{background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.3)}
.ai-f-verdict.error{background:rgba(227,174,162,.12);color:#e8a838;border:1px solid rgba(227,174,162,.3)}
.ai-f-verdict.timedout{background:rgba(227,174,162,.12);color:#e8a838;border:1px solid rgba(227,174,162,.3)}
.ai-finding .ai-f-reason{color:#c9d1d9;font-size:12px;font-family:monospace;line-height:1.5;margin-top:6px}
.ai-finding .ai-f-detail{color:#484f58;font-size:11px;font-family:monospace;margin-top:4px;word-break:break-all}
.ai-summary{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:14px;margin-bottom:16px;display:none}
.ai-summary.show{display:block}
.ai-summary .ai-s-verdict{font-size:14px;font-family:monospace;font-weight:bold;margin-bottom:6px}
.ai-summary .ai-s-verdict.threat{color:#f85149}
.ai-summary .ai-s-verdict.clean{color:#3fb950}
.ai-summary .ai-s-counts{color:#8b949e;font-size:11px;font-family:monospace}
.ai-modal .ai-close{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:8px 20px;font-family:monospace;font-size:12px;border-radius:4px;cursor:pointer;display:none}
.ai-modal .ai-close:hover{background:#30363d;border-color:#484f58}
.legend-btn{background:none;border:1px solid #2a3f5f;color:#58a6ff;font-family:monospace;font-size:0.72rem;padding:3px 10px;cursor:pointer;border-radius:3px;margin-bottom:20px;margin-left:8px}
.legend-btn:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.legend-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:10001;align-items:center;justify-content:center}
.legend-overlay.open{display:flex}
.legend-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:32px 36px;width:620px;max-width:94vw;max-height:85vh;overflow-y:auto;font-family:monospace;color:#c9d1d9;line-height:1.7}
.legend-modal h2{color:#58a6ff;font-size:16px;letter-spacing:2px;margin-bottom:20px;padding-bottom:10px;border-bottom:1px solid #21262d}
.legend-row{display:flex;align-items:flex-start;gap:14px;padding:10px 0;border-bottom:1px solid #161b22}
.legend-row:last-child{border-bottom:none}
.legend-badge{min-width:200px;font-size:12px;font-weight:bold;font-family:monospace}
.legend-desc{font-size:11px;color:#8b949e;line-height:1.6}
.legend-close{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:10px 24px;font-family:monospace;font-size:12px;border-radius:4px;cursor:pointer;margin-top:20px;display:block}
.legend-close:hover{background:#30363d;border-color:#484f58}
.vrd-help{color:#58a6ff;cursor:pointer;font-size:0.72rem;margin-left:4px;text-decoration:none}
.vrd-help:hover{text-decoration:underline}
.v2-banner{background:linear-gradient(90deg,#1f6feb 0%,#388bfd 100%);border:none;border-radius:6px;padding:12px 20px;margin-bottom:20px;cursor:pointer;display:flex;align-items:center;gap:14px;width:100%;text-align:left;font-family:monospace}
.v2-banner:hover{opacity:0.9}
.v2-banner .v2-tag{background:#fff;color:#1f6feb;font-size:10px;font-weight:bold;padding:3px 8px;border-radius:3px;letter-spacing:1px;white-space:nowrap}
.v2-banner .v2-text{color:#fff;font-size:13px}
.v2-banner .v2-arrow{color:rgba(255,255,255,0.7);font-size:16px;margin-left:auto}
.v2-banner .v2-dismiss{background:rgba(255,255,255,0.2);border:none;color:#fff;font-family:monospace;font-size:11px;padding:4px 10px;border-radius:3px;cursor:pointer;white-space:nowrap;margin-left:8px}
.v2-banner .v2-dismiss:hover{background:rgba(255,255,255,0.35)}
.v2-mini{background:none;border:1px solid #2a3f5f;color:#58a6ff;font-family:monospace;font-size:0.72rem;padding:3px 10px;cursor:pointer;border-radius:3px;margin-bottom:20px;display:none}
.v2-mini:hover{border-color:#58a6ff;background:rgba(88,166,255,.08)}
.wn-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:10001;align-items:center;justify-content:center}
.wn-overlay.open{display:flex}
.wn-modal{background:#0d1117;border:1px solid #21303f;border-radius:8px;padding:32px 36px;width:720px;max-width:94vw;max-height:85vh;overflow-y:auto;font-family:monospace;color:#c9d1d9;line-height:1.7}
.wn-modal h2{color:#58a6ff;font-size:16px;letter-spacing:2px;margin-bottom:20px;padding-bottom:10px;border-bottom:1px solid #21262d}
.wn-modal h3{color:#58a6ff;font-size:13px;letter-spacing:1px;margin-top:24px;margin-bottom:10px}
.wn-modal p{font-size:12px;margin-bottom:10px}
.wn-modal ul{font-size:12px;margin:8px 0 12px 20px}
.wn-modal li{margin-bottom:6px}
.wn-modal .wn-highlight{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:14px;margin:12px 0;font-size:12px}
.wn-modal .wn-green{color:#3fb950}
.wn-modal .wn-red{color:#f85149}
.wn-modal .wn-blue{color:#58a6ff}
.wn-modal .wn-dim{color:#8b949e}
.wn-modal table{width:100%;border-collapse:collapse;margin:12px 0;font-size:11px}
.wn-modal th{background:#161b22;color:#58a6ff;text-align:left;padding:8px 10px;border:1px solid #21262d;font-size:10px;text-transform:uppercase;letter-spacing:1px}
.wn-modal td{padding:8px 10px;border:1px solid #21262d}
.wn-modal .wn-close{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:10px 24px;font-family:monospace;font-size:12px;border-radius:4px;cursor:pointer;margin-top:20px;display:block}
.wn-modal .wn-close:hover{background:#30363d;border-color:#484f58}
</style>
</head>
<body>
<div id="login">
  <div class="lbox">
    <h1>RATCATCHER 2.0</h1>
    <p style="text-align:center;color:#58a6ff;font-size:0.9rem;cursor:pointer;margin-bottom:28px" onclick="document.getElementById('wn-overlay').classList.add('open')"><span style="text-decoration:underline">Read What's New</span> &rarr;</p>
    <form id="lf">
      <input type="password" id="pw" placeholder="Admin password" autocomplete="current-password">
      <button type="submit" class="btn">Sign In</button>
      <div class="lerr" id="lerr"></div>
    </form>
  </div>
</div>
<div id="dash">
  <div class="hdr">
    <h1>RATCATCHER 2.0</h1>
    <span class="badge">Manager Dashboard</span>
    <button class="gear" id="admtog" title="Admin Tools">&#9881; Admin</button>
    <button class="gear" id="logout" title="Sign out">&#9211; Logout</button>
  </div>
  <button class="v2-banner" id="v2banner" onclick="openWhatsNew()">
    <span class="v2-tag">v2.0</span>
    <span class="v2-text">RatCatcher 2.0 is here - AI-powered finding verification is now built in. <b>Click to learn what's new.</b></span>
    <span class="v2-arrow">&rarr;</span>
    <span class="v2-dismiss" onclick="event.stopPropagation();dismissBanner()">Got it</span>
  </button>
  <button class="v2-mini" id="v2mini" onclick="openWhatsNew()">&#9432; What's New in v2.0</button>
  <button class="legend-btn" onclick="openLegend()">&#9432; Status Legend</button>
  <div class="stats">
    <div class="stat selected" id="f-all"><div class="lbl">Total Scans</div><div class="val" id="s-total">-</div></div>
    <div class="stat clean" id="f-clean"><div class="lbl">Clean</div><div class="val" id="s-clean">-</div></div>
    <div class="stat comp" id="f-comp"><div class="lbl">Compromised</div><div class="val" id="s-comp">-</div></div>
    <div class="stat pos" id="f-pos"><div class="lbl">Positive Findings</div><div class="val" id="s-pos">-</div></div>
    <div class="stat rvw" id="f-reviewed"><div class="lbl">Reviewed</div><div class="val" id="s-reviewed">-</div></div>
    <div class="stat nrvw" id="f-await"><div class="lbl">Awaiting Review</div><div class="val" id="s-await">-</div></div>
  </div>
  <div class="search">
    <input type="text" id="srch" placeholder="Search hostname or username...">
    <button class="clr" id="srchclr">Clear</button>
  </div>
  <div class="tblw">
    <table>
      <thead><tr>
        <th>Submitted</th><th>Hostname</th><th>User</th>
        <th>Duration</th><th>Verdict <a class="vrd-help" onclick="openLegend()">?</a></th><th>Actions</th>
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
<div class="legend-overlay" id="legend-overlay">
  <div class="legend-modal">
    <h2>STATUS LEGEND</h2>
    <div class="legend-row"><span class="legend-badge" style="color:#00ff41">[+] CLEAN</span><span class="legend-desc">No suspicious findings were detected during the scan. No action required.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#ff4444">[!] COMPROMISED</span><span class="legend-desc">One or more findings were flagged by the scanner. Does not necessarily mean the machine is infected - findings need review.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#e8a838">[...] AI Evaluating</span><span class="legend-desc">Gemma 4 AI is currently analysing the findings. Results will appear automatically within 30-60 seconds.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#ff4444">[!] AI Verified Compromise</span><span class="legend-desc">AI has confirmed one or more findings match known attack indicators. This requires manager review and certification.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#3fb950">[~] AI Verified RAT Free!</span><span class="legend-desc">AI has determined all findings are false positives - normal system activity unrelated to the attack.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#3fb950">[+] AI Verified Clean</span><span class="legend-desc">No findings to evaluate. The scan was clean.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#e8a838">[!] AI Partial - Re-Evaluate</span><span class="legend-desc">AI evaluation timed out on some findings. Click Re-Evaluate to retry. Findings that were evaluated are still available.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#e8a838">Awaiting Manager Review</span><span class="legend-desc">AI confirmed a compromise but no manager has certified the finding yet. A manager must open the Technical Report, review the findings, and sign off.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#3fb950">Certified by [Name]</span><span class="legend-desc">A manager has reviewed the AI-verified compromise, communicated with the affected employee, and certified the finding. The manager's name and timestamp are recorded for audit.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#f85149">POSITIVE FINDING</span><span class="legend-desc">At least one finding has been confirmed as a real threat, either by AI or manual review.</span></div>
    <div class="legend-row"><span class="legend-badge" style="color:#3fb950">REVIEWED</span><span class="legend-desc">All findings have been reviewed and acknowledged as false positives. No threats found.</span></div>
    <button class="legend-close" onclick="document.getElementById('legend-overlay').classList.remove('open')">Close</button>
  </div>
</div>
<div class="wn-overlay" id="wn-overlay">
  <div class="wn-modal">
    <h2>RATCATCHER 2.0 - WHAT'S NEW</h2>
    <p class="wn-dim">For All Managers and Security Reviewers</p>

    <h3>What Changed?</h3>
    <p>RatCatcher 2.0 adds <b class="wn-blue">automatic AI-powered finding verification</b>. When a scan is submitted, our AI (Gemma 4) analyses every finding immediately - no manual steps needed. By the time you open the dashboard, the AI has already determined what is a real threat and what is a false positive.</p>
    <div class="wn-highlight"><b class="wn-green">Everything you already know still works exactly the same.</b> The Technical Reports, the Acknowledge/Confirm Threat buttons, the Copilot Agent workflow, the dashboard filters - nothing has changed or been removed. The AI is purely an addition.</div>

    <h3>Automatic AI Evaluation</h3>
    <p>Every scan is now automatically evaluated by AI as soon as it is submitted. You do not need to click anything - the AI works in the background. When you open the dashboard:</p>
    <ul>
      <li><b class="wn-green">[~] AI Verified RAT Free!</b> - AI determined all findings are false positives. No action needed.</li>
      <li><b class="wn-red">[!] AI Verified Compromise</b> - AI confirmed one or more real threats. Requires your review and certification.</li>
      <li><b style="color:#e8a838">[...] AI Evaluating</b> - AI is still processing. Results appear automatically within 30-60 seconds.</li>
    </ul>

    <h3>Manager Certification (New)</h3>
    <p>When AI confirms a compromise, the dashboard shows <b style="color:#e8a838">Awaiting Manager Review</b>. Here is what you do:</p>
    <ul>
      <li>Click <b class="wn-red">Review &amp; Certify</b> to open the Technical Report.</li>
      <li>Review all findings and AI verdicts shown inline on each finding.</li>
      <li>At the top of the report, click <b class="wn-red">Sign &amp; Certify</b>.</li>
      <li>Enter your first and last name to certify that you have reviewed the compromise and notified the affected employee.</li>
      <li>The report closes and the dashboard updates to show <b class="wn-green">Certified by [Your Name]</b>.</li>
    </ul>
    <p>This creates an audit trail linking every confirmed threat to the manager who reviewed it.</p>

    <h3>AI Verdicts in Technical Reports</h3>
    <p>When you open a Technical Report, each finding now shows the AI's assessment directly:</p>
    <ul>
      <li><b class="wn-red">AI: CONFIRMED THREAT</b> - Finding matches a known attack indicator, with an explanation of why.</li>
      <li><b class="wn-green">AI: FALSE POSITIVE</b> - Finding is normal system activity, with the AI's reasoning.</li>
    </ul>
    <p>The Acknowledge Finding and Confirm Threat buttons still work exactly as before - use them to record your final decision after reviewing the AI's assessment.</p>

    <h3>Status Legend</h3>
    <p>Click the <b class="wn-blue">Status Legend</b> button or the <b class="wn-blue">?</b> next to the Verdict column header to see a full explanation of every status badge and what action is required.</p>

    <h3>Updated Threat Intelligence</h3>
    <p>The AI now uses the latest threat intelligence from Elastic Security Labs, Unit42, Microsoft, and Google Threat Intelligence, including newly discovered IOCs, payload hashes, and the confirmed attribution to a North Korean state actor.</p>

    <h3>Faster Scans</h3>
    <p>The scanner now skips directories that cannot contain Node.js projects (media folders, drivers, virtual machines, etc.), reducing scan time significantly.</p>

    <h3>Do I Still Need to Use the Copilot Agent?</h3>
    <div class="wn-highlight"><b>No, but you can if you prefer.</b> The original workflow described in the How-To guide still works exactly as before. You can use AI only, Copilot only, or both for a second opinion. The AI does not automatically acknowledge or confirm findings - <b>you still make the final decision</b>.</div>

    <h3>Quick Comparison</h3>
    <table>
      <tr><th></th><th>v1 (Manual)</th><th>v2 (AI-Powered)</th></tr>
      <tr><td class="wn-dim">Finding evaluation</td><td>Copy/paste to Copilot</td><td>Automatic on submission</td></tr>
      <tr><td class="wn-dim">Time to evaluate</td><td>1-2 min per finding</td><td>10-30 sec (automatic)</td></tr>
      <tr><td class="wn-dim">Threat accountability</td><td>None</td><td>Manager certification with name</td></tr>
      <tr><td class="wn-dim">AI verdicts in reports</td><td>No</td><td>Yes - inline on each finding</td></tr>
      <tr><td class="wn-dim">Downloadable AI report</td><td>No</td><td>Yes (CSV)</td></tr>
      <tr><td class="wn-dim">Status legend</td><td>No</td><td>Yes - built into dashboard</td></tr>
      <tr><td class="wn-dim">Threat intelligence</td><td>Initial disclosure only</td><td>Latest from 4+ security vendors</td></tr>
      <tr><td class="wn-dim">Can I still use Copilot?</td><td>Yes</td><td>Yes - nothing removed</td></tr>
    </table>

    <p class="wn-dim">Questions? Contact the DevOps team.</p>
    <button class="wn-close" onclick="document.getElementById('wn-overlay').classList.remove('open')">Close</button>
  </div>
</div>
<div class="cert-overlay" id="cert-overlay">
  <div class="cert-modal">
    <h3>MANAGER CERTIFICATION</h3>
    <p>You are certifying that you have reviewed this AI-verified compromise, communicated with the affected employee, and instructed them to disconnect.</p>
    <p style="color:#c9d1d9" id="cert-host"></p>
    <input type="text" id="cert-name" placeholder="Enter your first and last name">
    <div class="cert-err" id="cert-err"></div>
    <div class="cert-btns">
      <button class="cert-cancel" id="cert-cancel">Cancel</button>
      <button class="cert-save" id="cert-save">Certify Verified</button>
    </div>
  </div>
</div>
<div class="ai-overlay" id="ai-overlay">
  <div class="ai-modal">
    <h3 id="ai-m-title">AI FINDING VERIFICATION</h3>
    <div class="ai-checklist" id="ai-m-checklist"></div>
    <div class="ai-status" id="ai-m-status"></div>
    <div class="ai-summary" id="ai-m-summary">
      <div class="ai-s-verdict" id="ai-m-verdict"></div>
      <div class="ai-s-counts" id="ai-m-counts"></div>
    </div>
    <div class="ai-findings" id="ai-m-findings"></div>
    <div style="display:flex;gap:10px;margin-top:16px">
      <button class="ai-close" id="ai-m-save" style="background:#1f6feb;border-color:#388bfd;color:#fff">Save CSV Report</button>
      <button class="ai-close" id="ai-m-close">Close</button>
    </div>
  </div>
</div>
<script>
function _vl(s){if(s.ai_verdict==='AI_PENDING')return'[...] AI Evaluating';if(s.ai_verdict==='AI_COMPROMISE')return'[!] AI Verified Compromise';if(s.ai_verdict==='AI_FALSE_POSITIVE')return'[~] AI Verified RAT Free!';if(s.ai_verdict==='AI_CLEAN')return'[+] AI Verified Clean';if(s.ai_verdict==='AI_PARTIAL')return'[!] AI Partial - Re-Evaluate';return s.verdict==='COMPROMISED'?'[!] COMPROMISED':'[+] CLEAN'}
function _certBadge(s){if(s.ai_verdict!=='AI_COMPROMISE')return'';if(s.certified_by)return'<span class="cert-done"> &#10003; Certified by '+esc(s.certified_by)+'</span>';return'<span class="await-review"> &#9888; Awaiting Manager Review</span>';}
const B=location.pathname.replace(/\\/dashboard$/,''),L=50;var pw='';let pg=1,refreshTimer=null,vfilter='',rfilter='',pfilter='',srchQ='';
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
  try{
    const r=await api('/api/stats'),d=await r.json();
    document.getElementById('s-total').textContent=(d.total??0).toLocaleString();
    document.getElementById('s-clean').textContent=(d.clean??0).toLocaleString();
    document.getElementById('s-comp').textContent=(d.compromised??0).toLocaleString();
    document.getElementById('s-pos').textContent=(d.positive??0).toLocaleString();
    document.getElementById('s-reviewed').textContent=(d.reviewed??0).toLocaleString();
    document.getElementById('s-await').textContent=(d.awaiting_cert??0).toLocaleString();
  }catch(e){console.error('loadStats',e)}
}
async function loadRows(){
  const r=await api('/api/submissions?page='+pg+'&limit='+L+(vfilter?'&verdict='+vfilter:'')+(pfilter?'&positive=1':'')+(rfilter!==''?'&reviewed='+rfilter:'')+(srchQ?'&search='+encodeURIComponent(srchQ):'')),d=await r.json();
  const tb=document.getElementById('tb');
  tb.innerHTML='';
  if(!d.submissions||!d.submissions.length){
    tb.innerHTML='<tr><td colspan="6" class="empty">No submissions yet.</td></tr>';
  } else {
    d.submissions.forEach(s=>{
      const tr=document.createElement('tr');
      tr.className=s.ai_verdict==='AI_FALSE_POSITIVE'?'ai-fp':s.verdict==='COMPROMISED'?'comp':'clean';
      const dt=new Date(s.submitted_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'});
      const ltag=s.is_latest?'<span class="latest">LATEST</span>':'';
      const aiBtn=s.ai_verdict==='AI_PENDING'
        ?'<span class="aibtn running" style="cursor:default">AI Evaluating...</span>'
        :s.ai_verdict==='AI_PARTIAL'
        ?'<button class="aibtn" style="border-color:#e8a838;color:#e8a838" onclick="aiEval(&#39;'+esc(s.id)+'&#39;,this,&#39;'+esc(s.hostname)+'&#39;,&#39;'+esc(s.username)+'&#39;)">&#9888; Re-Evaluate</button>'
        :'';
      tr.innerHTML='<td>'+esc(dt)+'</td><td>'+esc(s.hostname)+ltag+'</td><td>'+esc(s.username)+'</td>'
        +'<td>'+esc(fmtDur(s.duration))+'</td>'
        +'<td class="vrd">'+_vl(s)+_certBadge(s)+(s.positive?'<span class="positive"> &#9888; POSITIVE FINDING</span>':s.reviewed?'<span class="reviewed"> &#10003; REVIEWED</span>':'')+'</td>'
        +'<td><button class="vbtn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;brief&#39;)">Exec Brief</button> <button class="vbtn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;full&#39;)">Technical Report</button>'
        +' '+aiBtn
        +(s.ai_verdict==='AI_COMPROMISE'&&!s.certified_by?' <button class="cert-btn" onclick="vw(&#39;'+esc(s.id)+'&#39;,&#39;full&#39;)">Review &amp; Certify</button>':'')
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
function setFilter(v,rv,pf){
  vfilter=v;rfilter=rv??'';pfilter=pf??'';pg=1;
  document.querySelectorAll('.stat').forEach(el=>el.classList.remove('selected'));
  if(pf)document.getElementById('f-pos').classList.add('selected');
  else if(rv==='1')document.getElementById('f-reviewed').classList.add('selected');
  else if(rv==='await')document.getElementById('f-await').classList.add('selected');
  else document.getElementById(v==='CLEAN'?'f-clean':v==='COMPROMISED'?'f-comp':'f-all').classList.add('selected');
  loadRows();
}
document.getElementById('f-all').addEventListener('click',()=>setFilter('','',''));
document.getElementById('f-clean').addEventListener('click',()=>setFilter('CLEAN','',''));
document.getElementById('f-comp').addEventListener('click',()=>setFilter('COMPROMISED','',''));
document.getElementById('f-pos').addEventListener('click',()=>setFilter('','','1'));
document.getElementById('f-reviewed').addEventListener('click',()=>setFilter('','1',''));
document.getElementById('f-await').addEventListener('click',function(){setFilter('','await','')});
let srchTimer=null;
document.getElementById('srch').addEventListener('input',function(){
  clearTimeout(srchTimer);
  srchTimer=setTimeout(()=>{srchQ=this.value.trim();pg=1;loadRows()},300);
});
document.getElementById('srchclr').addEventListener('click',()=>{
  document.getElementById('srch').value='';srchQ='';pg=1;loadRows();
});
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
function openAiModal(title){
  document.getElementById('ai-m-title').textContent=title||'AI FINDING VERIFICATION';
  document.getElementById('ai-m-findings').innerHTML='';
  document.getElementById('ai-m-checklist').innerHTML='';
  document.getElementById('ai-m-summary').classList.remove('show');
  document.getElementById('ai-m-close').style.display='none';
  document.getElementById('ai-m-save').style.display='none';
  document.getElementById('ai-m-status').className='ai-status';
  document.getElementById('ai-m-status').innerHTML='';
  document.getElementById('ai-overlay').classList.add('open');
  resetCsvData();
}
function addCheckItem(text,state){
  var el=document.createElement('div');
  el.className='ai-check-item '+(state||'active');
  var icon=state==='done'?'&#10003;':state==='err'?'&#10007;':'&#8635;';
  el.innerHTML='<span class="ai-chk">'+icon+'</span> '+esc(text);
  document.getElementById('ai-m-checklist').appendChild(el);
  return el;
}
function completeCheckItem(el,text){
  el.className='ai-check-item done';
  el.innerHTML='<span class="ai-chk">&#10003;</span> '+esc(text||el.textContent.slice(2));
}
function failCheckItem(el,text){
  el.className='ai-check-item err';
  el.innerHTML='<span class="ai-chk">&#10007;</span> '+esc(text||el.textContent.slice(2));
}
function wait(ms){return new Promise(function(r){setTimeout(r,ms)})}
async function ensureModelReady(){
  var chk=addCheckItem('Connecting to AI server...','active');
  await wait(800);
  try{
    var sr=await fetch(B+'/api/ai-status',{headers:{'X-Admin-Password':pw}});
    var sd=await sr.json();
  }catch(e){
    failCheckItem(chk,'Could not reach AI server  - '+e.message);
    document.getElementById('ai-m-close').style.display='block';
    return false;
  }
  if(sd.status==='not_configured'){
    failCheckItem(chk,'AI verification is not configured on this server');
    document.getElementById('ai-m-close').style.display='block';
    return false;
  }
  completeCheckItem(chk,'AI server connected');
  await wait(500);
  var modelChk=addCheckItem('Checking Gemma 4 (31B) model status...','active');
  await wait(800);
  if(sd.loaded){
    completeCheckItem(modelChk,'Gemma 4 (31B) is loaded in GPU memory and ready');
    await wait(500);
    return true;
  }
  completeCheckItem(modelChk,'Model not currently in GPU memory');
  await wait(400);
  var loadChk=addCheckItem('Loading Gemma 4 (31B) into GPU memory... This may take 1-2 minutes','active');
  try{
    var wr=await fetch(B+'/api/ai-warmup',{method:'POST',headers:{'X-Admin-Password':pw}});
    var wd=await wr.json();
    if(!wr.ok){
      failCheckItem(loadChk,'Failed to load model - '+(wd.error||'unknown error'));
      document.getElementById('ai-m-close').style.display='block';
      return false;
    }
    completeCheckItem(loadChk,'Gemma 4 (31B) loaded successfully');
    await wait(500);
    return true;
  }catch(e){
    // Cloudflare 524 or network timeout - model may still be loading
    loadChk.innerHTML='<span class="ai-chk">&#8635;</span> Model is loading into GPU memory... Polling for readiness';
    var maxPolls=18;
    for(var p=0;p<maxPolls;p++){
      await wait(10000);
      loadChk.innerHTML='<span class="ai-chk">&#8635;</span> Waiting for model to load... ('+(p+1)*10+'s)';
      try{
        var pr=await fetch(B+'/api/ai-status',{headers:{'X-Admin-Password':pw}});
        var ps=await pr.json();
        if(ps.loaded){
          completeCheckItem(loadChk,'Gemma 4 (31B) loaded successfully');
          await wait(500);
          return true;
        }
      }catch(e2){}
    }
    failCheckItem(loadChk,'Model did not load within 3 minutes');
    document.getElementById('ai-m-close').style.display='block';
    return false;
  }
}
function closeAiModal(){document.getElementById('ai-overlay').classList.remove('open')}
document.getElementById('ai-m-close').addEventListener('click',closeAiModal);
var aiCsvRows=[];
function resetCsvData(){aiCsvRows=[];}
function addCsvRow(hostname,username,category,verdict,reason,detail){
  aiCsvRows.push({hostname:hostname,username:username,category:category,verdict:verdict,reason:reason,detail:detail});
}
function downloadCsv(){
  var header='Hostname,Username,Category,AI Verdict,AI Reasoning,Finding Detail';
  var rows=aiCsvRows.map(function(r){
    return [r.hostname,r.username,r.category,r.verdict,r.reason,r.detail].map(function(f){
      return '"'+String(f||'').replace(/"/g,'""')+'"';
    }).join(',');
  });
  var csv=header+'\\n'+rows.join('\\n');
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8;'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='RatCatcher-AI-Report-'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
}
document.getElementById('ai-m-save').addEventListener('click',downloadCsv);
function verdictClass(v){return(v||'').toLowerCase().replace(/\s/g,'')}
function verdictLabel(v){
  switch(v){
    case 'Confirmed':return'CONFIRMED THREAT';case 'Likely':return'LIKELY THREAT';
    case 'Unlikely':return'UNLIKELY';case 'FalsePositive':return'FALSE POSITIVE';
    case 'TimedOut':return'TIMED OUT  - RE-EVALUATE';
    default:return v||'UNKNOWN';
  }
}
function addFindingToModal(f){
  var el=document.createElement('div');el.className='ai-finding';
  el.innerHTML='<div class="ai-f-hdr">'
    +'<span class="ai-f-cat">'+esc(f.category)+'</span>'
    +'<span class="ai-f-verdict '+verdictClass(f.verdict)+'">'+verdictLabel(f.verdict)+'</span>'
    +'</div>'
    +(f.reason?'<div class="ai-f-reason">'+esc(f.reason)+'</div>':'')
    +(f.description?'<div class="ai-f-detail">'+esc(f.description)+'</div>':'');
  document.getElementById('ai-m-findings').appendChild(el);
}
async function aiEval(id,btn,hostname,username){
  btn.disabled=true;btn.classList.add('running');btn.textContent='Evaluating...';
  openAiModal('AI FINDING VERIFICATION');
  var ready=await ensureModelReady();
  if(!ready){btn.disabled=false;btn.classList.remove('running');btn.textContent='AI Eval';return;}
  var evalChk=addCheckItem('Analyzing findings with Gemma 4 (31B)...','active');
  try{
    var r=await fetch(B+'/api/submissions/'+id+'/ai-verify',{method:'POST',headers:{'X-Admin-Password':pw}});
    var d=await r.json();
    if(!r.ok){
      failCheckItem(evalChk,'Analysis failed  - '+(d.error||'status '+r.status));
      document.getElementById('ai-m-close').style.display='block';
      btn.disabled=false;btn.classList.remove('running');btn.textContent='AI Eval';
      return;
    }
    completeCheckItem(evalChk,'Analysis complete  - '+d.findings_total+' finding(s) evaluated');
    var vr=await fetch(B+'/api/submissions/'+id+'/ai-verdicts',{headers:{'X-Admin-Password':pw}});
    var vd=await vr.json();
    if(vr.ok&&vd.verdicts&&vd.verdicts.length){
      vd.verdicts.forEach(function(f){
        addFindingToModal(f);
        addCsvRow(hostname||'',username||'',f.category,verdictLabel(f.verdict),f.reason,f.description);
      });
    }
    var sum=document.getElementById('ai-m-summary');
    var sv=document.getElementById('ai-m-verdict');
    var sc=document.getElementById('ai-m-counts');
    if(d.ai_verdict==='AI_COMPROMISE'){
      sv.className='ai-s-verdict threat';
      sv.textContent='RESULT: CONFIRMED COMPROMISE';
    } else if(d.ai_verdict==='AI_FALSE_POSITIVE'){
      sv.className='ai-s-verdict clean';
      sv.textContent='RESULT: FALSE POSITIVE  - RAT Free';
    } else {
      sv.className='ai-s-verdict clean';
      sv.textContent='RESULT: CLEAN';
    }
    var b=d.breakdown||{};
    sc.textContent='Findings analyzed: '+d.findings_total+' | Confirmed: '+(b.confirmed||0)+' | Likely: '+(b.likely||0)+' | Unlikely: '+(b.unlikely||0)+' | False Positive: '+(b.falsePositive||0);
    sum.classList.add('show');
    document.getElementById('ai-m-save').style.display='block';
    document.getElementById('ai-m-close').style.display='block';
    btn.outerHTML='<span class="ai-done">&#10003; AI Reviewed</span>';
    await Promise.all([loadStats(),loadRows()]);
  }catch(e){
    failCheckItem(evalChk,'Analysis failed  - '+e.message);
    document.getElementById('ai-m-close').style.display='block';
    btn.disabled=false;btn.classList.remove('running');btn.textContent='AI Eval';
  }
}
document.getElementById('aiallbtn').addEventListener('click',async function(){
  this.disabled=true;this.textContent='Loading...';
  openAiModal('BULK AI VERIFICATION');
  var findChk=addCheckItem('Finding unreviewed submissions...','active');
  try{
    var r=await fetch(B+'/api/submissions?page=1&limit=100&reviewed=0',{headers:{'X-Admin-Password':pw}});
    var d=await r.json();
    var pending=(d.submissions||[]).filter(function(s){return !s.ai_verdict&&s.verdict==='COMPROMISED'});
    if(!pending.length){this.disabled=false;this.textContent='AI Evaluate All';completeCheckItem(findChk,'No unreviewed submissions to evaluate');document.getElementById('ai-m-close').style.display='block';return;}
    completeCheckItem(findChk,'Found '+pending.length+' unreviewed submission(s)');
    document.getElementById('ai-m-title').textContent='BULK AI VERIFICATION  - '+pending.length+' SUBMISSION(S)';
    var ready=await ensureModelReady();
    if(!ready){this.disabled=false;this.textContent='AI Evaluate All';return;}
    addCheckItem('Starting bulk analysis...','done');
    var totalThreats=0,totalClean=0,totalErr=0;
    for(var i=0;i<pending.length;i++){
      var sub=pending[i];
      var status=document.getElementById('ai-m-status');
      status.innerHTML='<span class="ai-spinner"></span> Evaluating submission '+(i+1)+' of '+pending.length+': '+esc(sub.hostname)+' ('+esc(sub.username)+')...';
      var hdr=document.createElement('div');
      hdr.style.cssText='color:#58a6ff;font-family:monospace;font-size:12px;font-weight:bold;letter-spacing:1px;margin-top:'+(i>0?'18':'0')+'px;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #21262d';
      hdr.innerHTML='&#9654; '+esc(sub.hostname)+' - '+esc(sub.username)+' ('+esc(new Date(sub.submitted_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'}))+')';
      document.getElementById('ai-m-findings').appendChild(hdr);
      try{
        var ar=await fetch(B+'/api/submissions/'+sub.id+'/ai-verify',{method:'POST',headers:{'X-Admin-Password':pw}});
        var ad=await ar.json();
        if(!ar.ok){
          var errEl=document.createElement('div');errEl.className='ai-finding';
          errEl.innerHTML='<div class="ai-f-hdr"><span class="ai-f-verdict error">ERROR</span></div><div class="ai-f-reason">'+esc(ad.error||'Failed')+'</div>';
          document.getElementById('ai-m-findings').appendChild(errEl);
          totalErr++;continue;
        }
        if(ad.ai_verdict==='AI_COMPROMISE')totalThreats++;else totalClean++;
        var verdictEl=document.createElement('div');
        verdictEl.style.cssText='font-family:monospace;font-size:11px;font-weight:bold;margin-bottom:6px;padding:4px 10px;border-radius:3px;display:inline-block;'
          +(ad.ai_verdict==='AI_COMPROMISE'?'background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3)':'background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.3)');
        verdictEl.textContent=ad.ai_verdict==='AI_COMPROMISE'?'CONFIRMED COMPROMISE':'FALSE POSITIVE  - RAT Free';
        document.getElementById('ai-m-findings').appendChild(verdictEl);
        var vr=await fetch(B+'/api/submissions/'+sub.id+'/ai-verdicts',{headers:{'X-Admin-Password':pw}});
        var vd=await vr.json();
        if(vr.ok&&vd.verdicts){vd.verdicts.forEach(function(f){
          addFindingToModal(f);
          addCsvRow(sub.hostname,sub.username,f.category,verdictLabel(f.verdict),f.reason,f.description);
        });}
      }catch(e){
        var errEl2=document.createElement('div');errEl2.className='ai-finding';
        errEl2.innerHTML='<div class="ai-f-hdr"><span class="ai-f-verdict error">ERROR</span></div><div class="ai-f-reason">'+esc(e.message)+'</div>';
        document.getElementById('ai-m-findings').appendChild(errEl2);
        addCsvRow(sub.hostname,sub.username,'','ERROR',e.message,'');
        totalErr++;
      }
    }
    var sum=document.getElementById('ai-m-summary');
    var sv=document.getElementById('ai-m-verdict');
    var sc=document.getElementById('ai-m-counts');
    sv.className='ai-s-verdict'+(totalThreats>0?' threat':' clean');
    sv.textContent=totalThreats>0?'BULK RESULT: '+totalThreats+' COMPROMISE(S) DETECTED':'BULK RESULT: ALL SUBMISSIONS CLEAR';
    sc.textContent='Submissions evaluated: '+pending.length+' | Threats: '+totalThreats+' | Clear: '+totalClean+(totalErr?' | Errors: '+totalErr:'');
    sum.classList.add('show');
    document.getElementById('ai-m-save').style.display='block';
    status.className='ai-status done';
    status.textContent='Bulk evaluation complete  - '+pending.length+' submission(s) processed';
    document.getElementById('ai-m-close').style.display='block';
    await Promise.all([loadStats(),loadRows()]);
  }catch(e){
    alert('Bulk AI eval error: '+e.message);
  }
  this.disabled=false;this.textContent='AI Evaluate All';
});
// -- Manager certification --
var certSubId=null;
function openCertify(id,hostname){
  certSubId=id;
  document.getElementById('cert-host').textContent='Submission: '+hostname;
  document.getElementById('cert-name').value='';
  document.getElementById('cert-err').textContent='';
  document.getElementById('cert-overlay').classList.add('open');
  setTimeout(function(){document.getElementById('cert-name').focus()},50);
}
document.getElementById('cert-cancel').addEventListener('click',function(){
  document.getElementById('cert-overlay').classList.remove('open');
});
document.getElementById('cert-overlay').addEventListener('click',function(e){
  if(e.target===this)this.classList.remove('open');
});
document.getElementById('cert-save').addEventListener('click',async function(){
  var name=document.getElementById('cert-name').value.trim();
  if(!name){document.getElementById('cert-err').textContent='Name is required.';return;}
  if(name.indexOf(' ')===-1){document.getElementById('cert-err').textContent='Please enter first and last name.';return;}
  this.disabled=true;this.textContent='Certifying...';
  try{
    var r=await fetch(B+'/api/submissions/'+certSubId+'/certify',{
      method:'POST',
      headers:{'X-Admin-Password':pw,'Content-Type':'application/json'},
      body:JSON.stringify({certified_by:name})
    });
    var d=await r.json();
    this.disabled=false;this.textContent='Certify Verified';
    if(!r.ok){document.getElementById('cert-err').textContent=d.error||'Certification failed.';return;}
    document.getElementById('cert-overlay').classList.remove('open');
    await Promise.all([loadStats(),loadRows()]);
  }catch(e){
    this.disabled=false;this.textContent='Certify Verified';
    document.getElementById('cert-err').textContent='Network error - please try again.';
  }
});
function openLegend(){document.getElementById('legend-overlay').classList.add('open')}
function openWhatsNew(){document.getElementById('wn-overlay').classList.add('open')}
function dismissBanner(){
  document.getElementById('v2banner').style.display='none';
  document.getElementById('v2mini').style.display='inline-block';
  try{localStorage.setItem('rc_v2_dismissed','1')}catch(e){}
}
function initBanner(){
  try{
    if(localStorage.getItem('rc_v2_dismissed')==='1'){
      document.getElementById('v2banner').style.display='none';
      document.getElementById('v2mini').style.display='inline-block';
    }
  }catch(e){}
}
pw=sessionStorage.getItem('rcpw')||'';
chkAuth().then(ok=>{if(ok){showDash();initBanner()}});
</script>
</body>
</html>`

export async function handleDashboard() {
  return new Response(HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
}
