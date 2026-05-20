<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>도깨비 관제 · __DOKKEBI_PH_PROJECT_NAME__</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#8b5cf6;
  --green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}
a{color:var(--accent);text-decoration:none}
/* Login */
#login{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-card{background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:40px;width:100%;max-width:360px;text-align:center}
.login-card .logo{font-size:40px;margin-bottom:8px}
.login-card h1{font-size:20px;margin-bottom:4px}
.login-card p{color:var(--muted);margin-bottom:24px;font-size:13px}
input[type=password]{width:100%;padding:10px 14px;background:#0d1117;
  border:1px solid var(--border);border-radius:8px;color:var(--text);
  font-size:14px;margin-bottom:12px;outline:none;transition:.2s}
input[type=password]:focus{border-color:var(--accent)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;
  background:var(--accent);color:#fff;border:none;border-radius:8px;
  font-size:14px;cursor:pointer;transition:.2s;font-weight:500}
.btn:hover{background:#7c3aed}.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-danger{background:#b91c1c}.btn-danger:hover{background:#991b1b}
.err-msg{color:var(--red);font-size:13px;margin-top:8px;min-height:18px}
/* Layout */
#app{display:none;height:100vh;overflow:hidden;flex-direction:column}
header{display:flex;align-items:center;gap:12px;padding:0 20px;
  height:52px;border-bottom:1px solid var(--border);
  background:var(--surface);flex-shrink:0}
header .logo{font-size:20px}
header h2{font-size:15px;font-weight:600;flex:1}
header .meta{font-size:12px;color:var(--muted)}
.layout{display:flex;flex:1;overflow:hidden}
/* Sidebar */
nav{width:200px;flex-shrink:0;border-right:1px solid var(--border);
  background:var(--surface);padding:12px 8px;display:flex;flex-direction:column;gap:2px}
nav button{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;
  background:none;border:none;border-radius:6px;color:var(--muted);
  font-size:13px;cursor:pointer;text-align:left;transition:.15s}
nav button:hover{background:rgba(139,92,246,.15);color:var(--text)}
nav button.active{background:rgba(139,92,246,.2);color:var(--accent);font-weight:500}
/* Main */
main{flex:1;overflow-y:auto;padding:20px}
.tab{display:none}.tab.active{display:block}
/* Stat cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px}
.card .label{font-size:12px;color:var(--muted);margin-bottom:4px}
.card .val{font-size:28px;font-weight:700}
.card .sub{font-size:11px;color:var(--muted);margin-top:2px}
.card.accent .val{color:var(--accent)}
.card.green .val{color:var(--green)}
.card.red .val{color:var(--red)}
.card.yellow .val{color:var(--yellow)}
/* Chart */
.chart-wrap{background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:16px;margin-bottom:20px}
.chart-title{font-size:13px;font-weight:600;color:var(--muted);margin-bottom:12px}
.bar-chart{display:flex;align-items:flex-end;gap:4px;height:80px}
.bar-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.bar{width:100%;background:var(--accent);border-radius:3px 3px 0 0;
  min-height:2px;transition:.3s;opacity:.7}
.bar-label{font-size:10px;color:var(--muted);white-space:nowrap}
/* Table */
.section-header{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:12px}
.section-header h3{font-size:14px;font-weight:600}
.section-header .actions{display:flex;gap:8px;align-items:center}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:13px}
thead{background:var(--surface)}
th{padding:10px 12px;text-align:left;font-weight:500;color:var(--muted);
  border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;
  word-break:break-all;max-width:320px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;
  font-size:11px;font-weight:500}
.badge-error{background:rgba(248,81,73,.15);color:var(--red)}
.badge-warn{background:rgba(210,153,34,.15);color:var(--yellow)}
.badge-info{background:rgba(88,166,255,.15);color:var(--blue)}
.badge-200{background:rgba(63,185,80,.15);color:var(--green)}
.badge-4xx{background:rgba(210,153,34,.15);color:var(--yellow)}
.badge-5xx{background:rgba(248,81,73,.15);color:var(--red)}
.badge-hmac{background:rgba(248,81,73,.15);color:var(--red)}
.badge-rate{background:rgba(210,153,34,.15);color:var(--yellow)}
.badge-sql{background:rgba(248,81,73,.15);color:var(--red)}
.stack{font-size:11px;color:var(--muted);white-space:pre-wrap;
  word-break:break-all;margin-top:4px;max-height:80px;overflow:hidden}
/* Pagination */
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;justify-content:flex-end}
.pagination button{padding:4px 10px;background:var(--surface);
  border:1px solid var(--border);border-radius:6px;color:var(--text);
  cursor:pointer;font-size:12px}
.pagination button:disabled{opacity:.4;cursor:not-allowed}
.pagination .info{font-size:12px;color:var(--muted)}
/* Misc */
.refresh-bar{display:flex;align-items:center;gap:8px;margin-bottom:16px;
  font-size:12px;color:var(--muted)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);
  animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.empty{padding:40px;text-align:center;color:var(--muted);font-size:13px}
.mode-badge{font-size:11px;padding:2px 8px;border-radius:12px;
  background:rgba(139,92,246,.2);color:var(--accent);font-weight:500}
select{background:var(--surface);border:1px solid var(--border);
  color:var(--text);padding:5px 8px;border-radius:6px;font-size:12px}
</style>
</head>
<body>

<!-- ─── 로그인 ─── -->
<div id="login">
  <div class="login-card">
    <div class="logo">👺</div>
    <h1>도깨비 관제</h1>
    <p>__DOKKEBI_PH_PROJECT_NAME__ · <span class="mode-badge">__DOKKEBI_PH_MODE__ 모드</span></p>
    <input type="password" id="pw" placeholder="관리자 비밀번호" autocomplete="current-password">
    <button class="btn" id="loginBtn" style="width:100%" onclick="doLogin()">로그인</button>
    <div class="err-msg" id="loginErr"></div>
  </div>
</div>

<!-- ─── 대시보드 ─── -->
<div id="app" style="display:none;flex-direction:column;height:100vh">
  <header>
    <span class="logo">👺</span>
    <h2>도깨비 관제 · __DOKKEBI_PH_PROJECT_NAME__</h2>
    <span class="meta" id="lastRefresh"></span>
    <span class="mode-badge">__DOKKEBI_PH_MODE__</span>
    <button class="btn btn-sm" onclick="doLogout()" style="margin-left:8px">로그아웃</button>
  </header>
  <div class="layout">
    <nav>
      <button class="active" data-tab="overview" onclick="switchTab('overview',this)">📊 개요</button>
      <button data-tab="errors"   onclick="switchTab('errors',this)">🔴 에러 로그</button>
      <button data-tab="security" onclick="switchTab('security',this)">🛡 보안 이벤트</button>
      <button data-tab="requests" onclick="switchTab('requests',this)">📋 요청 기록</button>
    </nav>
    <main>

      <!-- 개요 탭 -->
      <div class="tab active" id="tab-overview">
        <div class="refresh-bar">
          <span class="dot"></span>
          <span>자동 새로고침 30초</span>
          <button class="btn btn-sm" onclick="loadOverview()">지금 새로고침</button>
        </div>
        <div class="cards">
          <div class="card accent"><div class="label">현재 접속자</div><div class="val" id="c-active">-</div><div class="sub" id="c-mode"></div></div>
          <div class="card green"><div class="label">요청 수 (24h)</div><div class="val" id="c-req">-</div></div>
          <div class="card red"><div class="label">에러 (24h)</div><div class="val" id="c-err">-</div></div>
          <div class="card yellow"><div class="label">보안 이벤트 (24h)</div><div class="val" id="c-sec">-</div></div>
        </div>
        <div class="chart-wrap">
          <div class="chart-title">요청 추이 (최근 7일)</div>
          <div class="bar-chart" id="trend-chart"><div class="empty">데이터 없음</div></div>
        </div>
      </div>

      <!-- 에러 탭 -->
      <div class="tab" id="tab-errors">
        <div class="section-header">
          <h3>에러 로그</h3>
          <div class="actions">
            <select id="errLevel" onchange="loadErrors(0)">
              <option value="">전체</option>
              <option value="error">error</option>
              <option value="warn">warn</option>
            </select>
            <button class="btn btn-sm btn-danger" onclick="clearErrors()">🗑 전체 삭제</button>
          </div>
        </div>
        <div class="table-wrap">
          <table><thead><tr>
            <th>시간</th><th>출처</th><th>레벨</th><th>메서드</th><th>경로</th><th>메시지</th>
          </tr></thead>
          <tbody id="err-body"></tbody></table>
        </div>
        <div class="pagination" id="err-page"></div>
      </div>

      <!-- 보안 탭 -->
      <div class="tab" id="tab-security">
        <div class="section-header">
          <h3>보안 이벤트</h3>
        </div>
        <div class="table-wrap">
          <table><thead><tr>
            <th>시간</th><th>유형</th><th>IP</th><th>경로</th><th>상세</th>
          </tr></thead>
          <tbody id="sec-body"></tbody></table>
        </div>
        <div class="pagination" id="sec-page"></div>
      </div>

      <!-- 요청 탭 -->
      <div class="tab" id="tab-requests">
        <div class="section-header">
          <h3>요청 기록</h3>
        </div>
        <div class="table-wrap">
          <table><thead><tr>
            <th>시간</th><th>메서드</th><th>경로</th><th>상태</th><th>응답(ms)</th><th>IP</th>
          </tr></thead>
          <tbody id="req-body"></tbody></table>
        </div>
        <div class="pagination" id="req-page"></div>
      </div>

    </main>
  </div>
</div>

<script>
'use strict';
const TOKEN_KEY = 'dok_admin_token';
let _token = sessionStorage.getItem(TOKEN_KEY) || '';
// 현재 페이지 경로 기준 베이스 URL 자동 감지
// serve/dev:   /_dokkebi/_panel   → /_dokkebi/_panel/auth
// serverless: /api/_dokkebi/_panel → /api/_dokkebi/_panel/auth
const _BASE = location.pathname.replace(/\/+$/, '');

// ── 인증 ──
async function doLogin() {
  const pw  = document.getElementById('pw').value;
  const btn = document.getElementById('loginBtn');
  const err = document.getElementById('loginErr');
  if (!pw) { err.textContent = '비밀번호를 입력하세요.'; return; }
  btn.disabled = true;
  try {
    const r = await fetch(_BASE + '/auth', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({password: pw})
    });
    const d = await r.json();
    if (!r.ok) { err.textContent = d.error || '인증 실패'; btn.disabled = false; return; }
    _token = d.token;
    sessionStorage.setItem(TOKEN_KEY, _token);
    document.getElementById('login').style.display = 'none';
    document.getElementById('app').style.display = 'flex';
    init();
  } catch(e) { err.textContent = '서버 연결 실패'; btn.disabled = false; }
}

function doLogout() {
  sessionStorage.removeItem(TOKEN_KEY); _token = '';
  document.getElementById('app').style.display = 'none';
  document.getElementById('login').style.display = 'flex';
  document.getElementById('pw').value = '';
}

document.getElementById('pw').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });

// ── 탭 전환 ──
let _currentTab = 'overview';
function switchTab(name, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  btn.classList.add('active');
  _currentTab = name;
  if (name==='errors')   loadErrors(0);
  if (name==='security') loadSecurity(0);
  if (name==='requests') loadRequests(0);
}

// ── API 헬퍼 ──
async function api(path) {
  const r = await fetch(_BASE + '/api/' + path, {
    headers: { 'Authorization': 'Bearer '+_token }
  });
  if (r.status === 401) { doLogout(); throw new Error('auth'); }
  return r.json();
}

// ── 개요 ──
async function loadOverview() {
  try {
    const d = await api('overview');
    document.getElementById('c-active').textContent = d.activeUsers ?? 0;
    document.getElementById('c-mode').textContent   = d.mode === 'serve' ? 'SSE 연결 기준' : '최근 5분 IP';
    document.getElementById('c-req').textContent    = (d.requests24h ?? 0).toLocaleString();
    document.getElementById('c-err').textContent    = d.errors24h ?? 0;
    document.getElementById('c-sec').textContent    = d.security24h ?? 0;
    document.getElementById('lastRefresh').textContent = '갱신: ' + new Date().toLocaleTimeString('ko-KR');
    renderTrend(d.trend || []);
  } catch(e) { if(e.message!=='auth') console.warn(e); }
}

function renderTrend(trend) {
  const el = document.getElementById('trend-chart');
  if (!trend.length) { el.innerHTML = '<div class="empty">요청 데이터 없음</div>'; return; }
  const max = Math.max(...trend.map(r => r.cnt), 1);
  el.innerHTML = trend.map(r => {
    const pct = Math.max(Math.round((r.cnt / max) * 100), 2);
    const day = r.day ? r.day.slice(5) : '';
    return '<div class="bar-col"><div class="bar" style="height:'+pct+'%"></div><div class="bar-label">'+day+'</div></div>';
  }).join('');
}

// ── 에러 로그 ──
let errOffset = 0, errTotal = 0;
async function loadErrors(off) {
  errOffset = off;
  const lv = document.getElementById('errLevel').value;
  try {
    const d = await api('errors?limit=50&offset='+off+(lv?'&level='+lv:''));
    errTotal = d.total || 0;
    const tb = document.getElementById('err-body');
    if (!d.rows?.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">에러 없음 ✅</td></tr>'; }
    else tb.innerHTML = d.rows.map(r => {
      const lv = r.level === 'error' ? 'error' : 'warn';
      return '<tr><td style="white-space:nowrap">'+fmtTs(r.ts)+'</td>'
        +'<td>'+esc(r.source||'')+'</td>'
        +'<td><span class="badge badge-'+lv+'">'+esc(r.level||'')+'</span></td>'
        +'<td>'+esc(r.method||'')+'</td>'
        +'<td style="color:var(--muted)">'+esc(r.path||'')+'</td>'
        +'<td>'+esc(r.message||'')+(r.stack?'<div class="stack">'+esc(r.stack)+'</div>':'')+'</td></tr>';
    }).join('');
    renderPager('err-page', errTotal, off, 50, loadErrors);
  } catch(e) { if(e.message!=='auth') console.warn(e); }
}

async function clearErrors() {
  if (!confirm('모든 에러 로그를 삭제할까요?')) return;
  await fetch(_BASE + '/api/errors/clear', {
    method:'POST', headers:{'Authorization':'Bearer '+_token}
  });
  loadErrors(0);
}

// ── 보안 이벤트 ──
let secOffset = 0, secTotal = 0;
async function loadSecurity(off) {
  secOffset = off;
  try {
    const d = await api('security?limit=50&offset='+off);
    secTotal = d.total || 0;
    const tb = document.getElementById('sec-body');
    const TYPE_LABELS = {
      hmac_fail:'HMAC 실패', rate_limit:'레이트 리밋', sql_inject:'SQL 인젝션', nonce_replay:'Nonce 재사용'
    };
    if (!d.rows?.length) { tb.innerHTML = '<tr><td colspan="5" class="empty">보안 이벤트 없음 ✅</td></tr>'; }
    else tb.innerHTML = d.rows.map(r => {
      const cls = r.type?.includes('sql')?'sql':r.type?.includes('rate')?'rate':'hmac';
      return '<tr><td style="white-space:nowrap">'+fmtTs(r.ts)+'</td>'
        +'<td><span class="badge badge-'+cls+'">'+esc(TYPE_LABELS[r.type]||r.type||'')+'</span></td>'
        +'<td style="color:var(--muted)">'+esc(r.ip||'')+'</td>'
        +'<td>'+esc(r.path||'')+'</td>'
        +'<td style="color:var(--muted);font-size:12px">'+esc(r.detail||'')+'</td></tr>';
    }).join('');
    renderPager('sec-page', secTotal, off, 50, loadSecurity);
  } catch(e) { if(e.message!=='auth') console.warn(e); }
}

// ── 요청 기록 ──
let reqOffset = 0, reqTotal = 0;
async function loadRequests(off) {
  reqOffset = off;
  try {
    const d = await api('requests?limit=50&offset='+off);
    reqTotal = d.total || 0;
    const tb = document.getElementById('req-body');
    if (!d.rows?.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">기록 없음</td></tr>'; }
    else tb.innerHTML = d.rows.map(r => {
      const sc  = r.status || 0;
      const cls = sc >= 500 ? '5xx' : sc >= 400 ? '4xx' : '200';
      return '<tr><td style="white-space:nowrap">'+fmtTs(r.ts)+'</td>'
        +'<td>'+esc(r.method||'')+'</td>'
        +'<td>'+esc(r.path||'')+'</td>'
        +'<td><span class="badge badge-'+cls+'">'+sc+'</span></td>'
        +'<td>'+(r.duration_ms!=null?r.duration_ms+'ms':'-')+'</td>'
        +'<td style="color:var(--muted)">'+esc(r.ip||'')+'</td></tr>';
    }).join('');
    renderPager('req-page', reqTotal, off, 50, loadRequests);
  } catch(e) { if(e.message!=='auth') console.warn(e); }
}

// ── 헬퍼 ──
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmtTs(ts) {
  if (!ts) return '-';
  try { return new Date(ts.endsWith('Z')?ts:ts+'Z').toLocaleString('ko-KR',{timeZone:'Asia/Seoul',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  catch { return ts; }
}
function renderPager(id, total, offset, limit, fn) {
  const el = document.getElementById(id);
  const pages = Math.ceil(total / limit);
  const cur   = Math.floor(offset / limit) + 1;
  el.innerHTML = '<button '+(cur<=1?'disabled':'')+' onclick="'+fn.name+'('+(offset-limit)+')">&laquo; 이전</button>'
    +'<span class="info">'+cur+' / '+Math.max(pages,1)+'페이지 (총 '+total+'건)</span>'
    +'<button '+(cur>=pages?'disabled':'')+' onclick="'+fn.name+'('+(offset+limit)+')">다음 &raquo;</button>';
}

// ── 초기화 ──
function init() {
  loadOverview();
  setInterval(loadOverview, 30_000);
}

// 이미 토큰이 있으면 바로 대시보드
if (_token) {
  document.getElementById('login').style.display = 'none';
  document.getElementById('app').style.display   = 'flex';
  init();
}
</script>
</body>
</html>